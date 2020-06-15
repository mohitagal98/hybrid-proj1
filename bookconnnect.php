<?php
//session_start();
// initializing variables

$email = "";
$password = "";
$errors = array(); 

// connect to the database
$db = mysqli_connect('database1', 'root', 'abc@123', 'bookingcalendar');
if (isset($_POST['signupbt'])) {

  $password = mysqli_real_escape_string($db, $_POST['psw']);
  $email = mysqli_real_escape_string ($db, $_POST['email']);
  $confirm = mysqli_real_escape_string($db, $_POST['psw-repeat']);
  if ($password === $confirm){
    if (count($errors) == 0) {
    $query = "INSERT into signup values ('$email','$password')";
    $results = mysqli_query($db, $query);
    
      header('location: login.php');
    }else 
    {
        echo "pass no match";
        header('Location: register.php');
    }
  }
  
}

?>