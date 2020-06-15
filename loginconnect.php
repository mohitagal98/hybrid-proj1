<?php
// initializing variables
$email= $_POST['uname'];
$password=$_POST['psw'];
$errors = array(); 

// connect to the database
$db = mysqli_connect('database1', 'root', 'abc@123', 'bookingcalendar');
if($db === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
$sql = "SELECT email,password FROM signup where email='$email' AND password='$password'";
if($result = mysqli_query($db, $sql)){
    if(mysqli_num_rows($result) > 0){
		session_start();
        $_SESSION['email']= $email;
        header("Location:calendar.php");
    } else{
        header("Location:login.php?error=1");
    }
}
 
// Close connection
mysqli_close($db);
?>