<?php
session_start();
if(!isset($_SESSION['email'])){
    header("Location:login.php");
}
function build_calendar($month, $year, $room){
     $mysqli = new mysqli('database1', 'root', 'abc@123', 'bookingcalendar');
     $stmt = $mysqli->prepare('select * from rooms');
     $rooms = "";
     $first_room = 0;
     $i = 0;
    if($stmt->execute()){
        $result = $stmt->get_result();
        if($result->num_rows>0){
            while($row = $result->fetch_assoc()){
                if($i==0){
                    $first_room = $row['id'];
                }
                $rooms.= "<option value='".$row['id']."'>".$row['name']."</option>";
                $i++;
            }
            
            $stmt->close();
        }
    }

    if($room != 0){
        $first_room = $room;
    }

    $stmt = $mysqli->prepare('select * from bookings where MONTH(date) = ? AND YEAR(date) = ? AND room_id = ?');
    $stmt->bind_param('ssi', $month, $year, $first_room);
    $bookings = array();
    if($stmt->execute()){
        $result = $stmt->get_result();
        if($result->num_rows>0){
            while($row = $result->fetch_assoc()){
                $bookings[] = $row['date'];
            }
            
            $stmt->close();
        }
    }

	$daysOfWeek = array('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday','Sunday');

	$firstDayOfMonth = mktime(0,0,0,$month,1,$year);

	$numberDays = date('t', $firstDayOfMonth);

	$dateComponents = getdate($firstDayOfMonth);

	$monthName = $dateComponents['month'];

	$dayOfWeek = $dateComponents['wday'];
    if($dayOfWeek==0){
        $dayOfWeek = 6;
    }else{
        $dayOfWeek = $dayOfWeek-1;
    }

	$dateToday = date('Y-m-d');

	$calendar = "
    <form id='room_select_form'>
    <div class='row'>
        <div class='col-md-6 col-md-offset-3 form-group'>
        <label>Select Room</label>
            <select class='form-control' id='room_select' name='room'>
                ".$rooms."
            </select>
            <input type='hidden' name='month' value='".$month."'>
            <input type='hidden' name='year' value='".$year."'>
        </div>
    </div>
    </form>

    <table class='table table-bordered'>";
	$calendar.= "<center><h2>$monthName $year</h2>";
	$calendar.= "<a class='btn btn-xs btn-primary' href='?month=".date('m', mktime(0, 0, 0, $month-1, 1, $year))."&year=".date('Y', mktime(0, 0, 0, $month-1, 1, $year))."'>Previous Month</a> ";

	$calendar.= "<a class='btn btn-xs btn-primary' href='?month=".date('m')."&year=".date('Y')."'>Current Month</a> ";

	$calendar.= "<a class='btn btn-xs btn-primary' href='?month=".date('m', mktime(0, 0, 0, $month+1, 1, $year))."&year=".date('Y', mktime(0, 0, 0, $month+1, 1, $year))."'>Next Month</a><center><br>";

	$calendar.="<tr>";

	foreach($daysOfWeek as $day){
		$calendar.="<th class='header'>$day</th>";
	}

	$currentDay = 1;

	$calendar.= "</tr><tr>";

	if($dayOfWeek>0){
		for($k=0;$k<$dayOfWeek;$k++){
			$calendar.="<td></td>"; 
		}
	}

	$month = str_pad($month, 2, "0", STR_PAD_LEFT);

	while($currentDay <= $numberDays){

		if($dayOfWeek == 7){
			$dayOfWeek = 0;
			$calendar.="</tr><tr>";
		}
		$currentDayRel = str_pad($currentDay, 2, "0", STR_PAD_LEFT);
		$date = "$year-$month-$currentDayRel";

		$dayname = strtolower(date('l', strtotime($date)));
            $eventNum = 0;
            $today = $date==date('Y-m-d')? "today" : "";
            if($dayname=='saturday' || $dayname=='sunday'){
                $calendar.="<td><h4>$currentDay</h4> <button class='btn btn-danger btn-xs'>Holiday</button>";
            }elseif($date<date('Y-m-d')){
             $calendar.="<td><h4>$currentDay</h4> <button class='btn btn-danger btn-xs'>N/A</button>";
         }else{

            $totalbookings = checkSlots($mysqli, $date);
            if ($totalbookings == 9){
                $calendar.="<td class='$today'><h4>$currentDay</h4> <a href='#' class='btn btn-danger btn-xs'>All Booked</a>";    
            }else{
                $availableslots = 9 - $totalbookings;
                $calendar.="<td class='$today'><h4>$currentDay</h4> <a href='book.php?date=".$date."' class='btn btn-success btn-xs'>Book</a><small><i> $availableslots slots left</i></small>";
            }
            
         }

		$calendar.="</td>";

		$currentDay++;
		$dayOfWeek++;
	}

	if($dayOfWeek != 7){
		$remainingDays = 7-$dayOfWeek;
		for($i=0;$i<$remainingDays;$i++){
			$calendar.="<td></td>";
		}
	}

	$calendar.="</tr>";
	$calendar.="</table>";

	echo $calendar;

}

function checkSlots($mysqli, $date){
    $stmt = $mysqli->prepare("select * from bookings where date = ?");
    $stmt->bind_param('s', $date);
    $totalbookings = 0;
    if($stmt->execute()){
        $result = $stmt->get_result();
        if($result->num_rows>0){
            while($row = $result->fetch_assoc()){
                $totalbookings++;
            }
            
            $stmt->close();
        }
    }

    return $totalbookings;
}

?>

<html>
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/css/bootstrap.min.css">
    <link rel="stylesheet" type="text/css" href="navigation.css">
	<style>
		@media only screen and (max-width: 760px),
        (min-device-width: 802px) and (max-device-width: 1020px) {

            /* Force table to not be like tables anymore */
            table, thead, tbody, th, td, tr {
                display: block;

            }
            
            

            .empty {
                display: none;
            }

            /* Hide table headers (but not display: none;, for accessibility) */
            th {
                position: absolute;
                top: -9999px;
                left: -9999px;
            }

            tr {
                border: 1px solid #ccc;
            }

            td {
                /* Behave  like a "row" */
                border: none;
                border-bottom: 1px solid #eee;
                position: relative;
                padding-left: 50%;
            }



            /*
		Label the data
		*/
            td:nth-of-type(1):before {
                content: "Sunday";
            }
            td:nth-of-type(2):before {
                content: "Monday";
            }
            td:nth-of-type(3):before {
                content: "Tuesday";
            }
            td:nth-of-type(4):before {
                content: "Wednesday";
            }
            td:nth-of-type(5):before {
                content: "Thursday";
            }
            td:nth-of-type(6):before {
                content: "Friday";
            }
            td:nth-of-type(7):before {
                content: "Saturday";
            }


        }

        /* Smartphones (portrait and landscape) ----------- */

        @media only screen and (min-device-width: 320px) and (max-device-width: 480px) {
            body {
                padding: 0;
                margin: 0;
            }
        }

        /* iPads (portrait and landscape) ----------- */

        @media only screen and (min-device-width: 802px) and (max-device-width: 1020px) {
            body {
                width: 495px;
            }
        }

        @media (min-width:641px) {
            table {
                table-layout: fixed;
            }
            td {
                width: 33%;
            }
        }
        
        .row{
            margin-top: 20px;
        }
        
        .today{
            background:yellow;
        }
	</style>
</head>
<body>

    <div class="topnav">
      <a class="active" href="index.php">Home</a>
      <a href="contact.php">Contact</a>
      <a href="login.php" target="_blank">My Account</a>
    </div>

	<div class="container">
		<div class="row">
			<div class="col-md-12">
				<?php
					$dateComponents = getdate();
					if(isset($_GET['month']) && isset($_GET['year'])){
                         $month = $_GET['month']; 			     
                         $year = $_GET['year'];
                     }else{
                     	$month = $dateComponents['mon'];
						$year = $dateComponents['year'];
                     }

                     if(isset($_GET['room'])){
                        $room = $_GET['room'];
                     }else{
                        $room = 0;
                     }
					
					echo build_calendar($month,$year,$room);
				?>
			</div>
		</div>
	</div>
    <script src="http://code.jquery.com/jquery-3.5.1.js" integrity="sha256-QWo7LDvxbWT2tbbQ97B53yJnYU3WhH/C8ycbRAkjPDc="
    crossorigin="anonymous"></script>

    <script>
        $("#room_select").change(function(){
            $("#room_select_form").submit();
        });

        $("room_select option[value='<?php echo $room; ?>']").attr('selected','selected');
    </script>

</body>
</html>