provider "aws" {
	region = "ap-south-1"
	profile = "mohit"
}

//********ssh key generation********************************
resource "tls_private_key" "keygen" {
  algorithm   = "RSA"
  
}

//*********Creating key pair in aws**************************
resource "aws_key_pair" "newKey" {
depends_on=[
	tls_private_key.keygen
]
  key_name   = "webkey1"
  public_key = tls_private_key.keygen.public_key_openssh
}


//**********Saving private key in local file.*****************
resource "local_file" "privatekey" {
depends_on=[
	aws_key_pair.newKey
]
    content     = tls_private_key.keygen.private_key_pem
    filename = "C:/Users/Dell/Downloads/webkey1.pem"
}


//*************Security rule with some ingress rule************
resource "aws_security_group" "SecGroup" {
depends_on=[
	local_file.privatekey
]
  name        = "SecurityGroup1"
  description = "Allow TLS inbound traffic"
  vpc_id      = "vpc-e7e4f98f"

  ingress {
    description = "For http users"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "For php admin users"
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "For ssh login if needed"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SecGroup"
  }
}



//*************Instance creation******************
resource "aws_instance" "ins1"{
depends_on=[
	aws_security_group.SecGroup
]
	ami = "ami-005956c5f0f757d37"
	instance_type = "t2.micro"
	key_name = "webkey1"
	security_groups = [ "SecurityGroup1" ]
	tags = {
		name = "linuxos"
	}
	connection{
		type = "ssh"
		user = "ec2-user"
		private_key = file("C:/Users/Dell/Downloads/webkey1.pem")
		host = aws_instance.ins1.public_ip
	}
	provisioner "remote-exec"{
		inline = [
			"sudo yum install docker -y",
			"sudo service docker start",
			"sudo chkconfig docker on",
			"sudo curl -L https://github.com/docker/compose/releases/download/1.26.0/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose",
			"sudo chmod +x /usr/local/bin/docker-compose",
			"sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose",
		]
	}
}

//************EBS creation***************************
resource "aws_ebs_volume" "ebs1" {
depends_on=[
  aws_instance.ins1
]
  availability_zone = aws_instance.ins1.availability_zone
  size              = 1

  tags = {
    Name = "Web Ebs"
  }
}

//***************AWS volume attachment****************
resource "aws_volume_attachment" "ebs_attach" {
depends_on=[
  aws_ebs_volume.ebs1
]
  device_name = "/dev/sdd"
  volume_id   = "${aws_ebs_volume.ebs1.id}"
  instance_id = "${aws_instance.ins1.id}"
  force_detach = true
}


//**************FORMAT_MOUNT***************************
resource "null_resource" "mount-part"{
depends_on=[
	aws_volume_attachment.ebs_attach
]
	connection{
		type = "ssh"
		user = "ec2-user"
		private_key = file("C:/Users/Dell/Downloads/webkey1.pem")
		host = aws_instance.ins1.public_ip
	}
	provisioner "remote-exec"{
		inline = [
			"sudo mkdir /storage",
			"sudo mkfs.ext4 /dev/xvdd",
			"sudo mount /dev/xvdd /storage",
			"sudo mkdir /storage/sqlstorage",
			"sudo mkdir /storage/phpstorage",
			"sudo rm -rf /storage/phpstorage/*",
			"sudo yum install git -y",
			"sudo git clone https://github.com/mohitagal98/hybrid-proj1.git",
			"sudo cp -rf hybrid-proj1/* /storage/phpstorage",
			"sudo cp -f hybrid-proj1/docker-compose.yml /home/ec2-user/",
			"sudo docker-compose up",

		]
	}
}


//****************S3-Bucket***************************
resource "aws_s3_bucket" "s3storage" {
  bucket = "mohitagarwal1231234"
  acl    = "public-read"
  force_destroy = true
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST"]
    allowed_origins = ["https://mohitagarwal1231234"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

//**************Adding S3 Object**********************
resource "aws_s3_bucket_object" "s3object" {
depends_on = [
	aws_s3_bucket.s3storage
]
  bucket = aws_s3_bucket.s3storage.bucket
  key    = "log-sign.jpg"
  source = "C:/Users/Dell/Downloads/is.jpg"
  acl = "public-read"
  
}




//*************AWS-CloudFront**************************************
resource "aws_cloudfront_distribution" "s3_distribution" {
depends_on = [
	aws_s3_bucket_object.s3object
]
  origin {
    domain_name = "${aws_s3_bucket.s3storage.bucket_regional_domain_name}"
    origin_id   = "${aws_s3_bucket.s3storage.id}"

    custom_origin_config {
            http_port = 80
            https_port = 443
            origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        }
    
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "SignUp image"
  default_root_object = "log-sign.jpg"


  custom_error_response {
        error_caching_min_ttl = 3000
        error_code = 404
        response_code = 200
        response_page_path = "/log-sign.jpg"
    }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${aws_s3_bucket.s3storage.id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "${aws_s3_bucket.s3storage.id}"

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${aws_s3_bucket.s3storage.id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["IN", "CA", "AU", "DE"]
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}