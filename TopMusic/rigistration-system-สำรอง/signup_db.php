<?php 

    session_start();
    require_once 'config.php';

    if (isset($_POST['signup'])) {
        $firstname = $_POST['firstname'];
        $lastname = $_POST['lastname'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        $c_password = $_POST['c_password'];
        $urole = 'user';

    if (empty($firstname)) {
      $_SERVER['error'] = 'กรุณากรอกชื่อ';
      header("Location: index.php");
    }else if (empty($lastname)) {
        $_SERVER['error'] = 'กรุณากรอกนามสกุล';
      header("Location: index.php");
    }else if (empty($email)) {
        $_SERVER['error'] = 'กรุณากรอกอีเมล';
      header("Location: index.php");
    }else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SERVER['error'] = 'อีเมลไม่ถูกต้อง';
      header("Location: index.php");
    }else if (empty($password)) {
        $_SERVER['error'] = 'กรุณากรอกรหัสผ่าน';
      header("Location: index.php");
    }else if (strlen($_POST['password']) >20 || strlen($_POST['password']) <5 ) {
        $_SERVER['error'] = 'รหัสผ่านต้องมีความยาวระหว่าง 5 ถึง 20 ตัวอักษร';
      header("Location: index.php");
    }else if (empty($c_password)) 
        $_SERVER['error'] = 'กรุณายืนยันรหัสผ่าน';
      header("Location: index.php");
    }else if ($password != $c_password) {
        $_SESSION['error'] = 'รหัสผ่านไม่ตรงกัน';
        header("Location: index.php");
    } else {
        try{

            $check_email = $conn->prepare("SELECT email FROM email WHERE email = :email");
            $check_email->bindParam(':email',$email);
            $check_email->execute();
            $row = $check_email->fetch(PDO::FETCH_ASSOC);

            if ($row['email'] == $email) {
                $_SESSION ['warning'] = "อีเมลนี้ได้ถูกใช้งานแล้ว <a href='signin.php'คลื๊กที่นี่></a> เพื่อเข้าสู่ระบบ";
                header("Location:index.php");
            }else if (!isset($_SESSION['error'])){
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("INSERT INTO user(firstname, lastname, email, password, urole) 
                                    VALUES(:firstname, :lastname, :email, :password, :urole)");
                $stmt->bindParam("firstname", $firstname);
                $stmt->bindParam("lastname", $lastname);
                $stmt->bindParam("email", $email);
                $stmt->bindParam("password", $password);
                $stmt->bindParam("urole", $urole);
                $stmt->execute();
                $SESSION['susccess'] = "สมัครสมาชิกเรียบร้อย! <a href='signin.php' class='alert-link></a> เพื่อเข้าสู่ระบบ";
                header("Location: index.php");
            }else {
                $SESSION['error'] = "มีบางอย่างผิดพลาด";
                header("Location: index.php");

            }

        } catch(PDOException $e) {
            echo $e->getMessage();
        }
    }

?>