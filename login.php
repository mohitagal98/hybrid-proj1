
<html>
<head>
  <title>Login page</title>
  <link rel="stylesheet" type="text/css" href="login.css">
  <link rel="stylesheet" type="text/css" href="navigation.css">
</head>
<body style="background-image: url('is.jpg'); background-repeat: no-repeat; background-size: cover;">
  <div class="topnav">
  <a class="active" href="index.php">Home</a>
  <a href="contact.php">Contact</a>
  <a href="login.php" target="_blank">My Account</a>
  </div>


  <div class="middle" style="width:800px; margin:0 auto;  padding-top: 25px;">
  <form action="loginconnect.php" method="post" style="border: 2px solid black;">
  <div class="imgcontainer" style="background-color: white; margin: 0px; padding-top: 10px;">
    <img src="avatar.png" alt="Avatar" class="avatar">
  </div>

  <div class="container" style="background-color: white;">
    <label for="uname"><b>Username</b></label>
    <input type="text" placeholder="Enter Email" name="uname" required>

    <label for="psw"><b>Password</b></label>
    <input type="password" placeholder="Enter Password" name="psw" required>

    <button type="submit">Login</button>
    <label>
      <input type="checkbox" checked="checked" name="remember"> Remember me
    </label>
  </div>
  <?php if(isset($_GET['error']))
    echo "<div>User does not exist.</div>";
    ?>

  <div class="container" style="background-color:#f1f1f1">
    <button type="button" class="cancelbtn" onclick="location.href='index.php';">Cancel</button>
    <span class="psw">New User <a href="signup.php">Sign Up</a></span>
  </div>
</form>
</div>
</body>
</html>