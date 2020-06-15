<html>
<head>
  <title> Contact</title>
  <link rel="stylesheet" type="text/css" href="index.css">
  <link rel="stylesheet" type="text/css" href="navigation.css">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Sofia">
</head>
<body style="background-image: url('is.jpg'); background-repeat: no-repeat; background-size: cover;">

  <div class="topnav">
  <a class="active" href="index.php">Home</a>
  <a href="contact.php">Contact</a>
  <a href="login.php" target="_blank">My Account</a>
  </div>
  <br>
  <div class="container" style="width:800px; margin:0 auto;">
  <a id = "contact"></a>
  <form action="">

    <label for="fname">First Name</label>
    <input type="text" id="fname" name="firstname" placeholder="Your name..">

    <label for="lname">Last Name</label>
    <input type="text" id="lname" name="lastname" placeholder="Your last name..">

    <label for="country">Country</label>
    <select id="country" name="country">
      <option value="australia">Australia</option>
      <option value="canada">Canada</option>
      <option value="usa">USA</option>
    </select>

    <label for="subject">Subject</label>
    <textarea id="subject" name="subject" placeholder="Write something.." style="height:200px"></textarea>

    <input type="submit" value="Submit">

  </form>
</div>
</body>
