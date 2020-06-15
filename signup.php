<?php 
include('bookconnnect.php');
?>

<html>
<head>
  <title>Signup</title>
  <link rel="stylesheet" type="text/css" href="Signup.css">
  <link rel="stylesheet" type="text/css" href="navigation.css">
</head>
<body style="background-image: url('is.jpg'); background-repeat: no-repeat; background-size: cover;">

	<div class="topnav">
  <a class="active" href="index.php">Home</a>
  <a href="contact.php">Contact</a>
  <a href="login.php" target="_blank">My Account</a>
	</div>


  <div class="middle" style="width:800px; margin:0 auto; padding-top: 25px;">
  <form action="" style="border:1px solid #ccc" method="POST">
  <div class="container">
    <h1>Sign Up</h1>
    <p>Please fill in this form to create an account.</p>
    <hr>

    <label for="email"><b>Email</b></label>
    <input type="text" placeholder="Enter Email" name="email" required>

    <label for="psw"><b>Password</b></label>
    <input type="password" placeholder="Enter Password" name="psw" required>

    <label for="psw-repeat"><b>Repeat Password</b></label>
    <input type="password" placeholder="Repeat Password" name="psw-repeat" required>

    <label>
      <input type="checkbox" checked="checked" name="remember" style="margin-bottom:15px"> Remember me
    </label>

    <p>By creating an account you agree to our <a href="#" style="color:dodgerblue">Terms & Privacy</a>.</p>

    <div class="clearfix">
      <button type="button" class="cancelbtn" onclick="location.href='index.php';">Cancel</button>
      <button type="submit" class="signupbtn" name="signupbt">Sign Up</button>
    </div>
  </div>
  </form>
</div>
</body>
</html>