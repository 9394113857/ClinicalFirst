use clinicalfirst;

CREATE TABLE `clinicalfirst`.`user_signup` (
  `user_signup_id` INT NOT NULL AUTO_INCREMENT,
  `user_id` VARCHAR(100) NULL,
  `user_name` VARCHAR(100) NULL,
  `user_mail_id` VARCHAR(100) NULL,
  `user_phone_number` VARCHAR(20) NULL,
  `user_password` VARCHAR(200) NOT NULL,
  `user_ip` VARCHAR(20) NOT NULL,
  `user_date_created` DATETIME NULL,
  `user_device` VARCHAR(50) NULL,
  PRIMARY KEY (`user_signup_id`),
  UNIQUE INDEX `user_id_UNIQUE` (`user_id` ASC) VISIBLE,
  UNIQUE INDEX `user_phone_number_UNIQUE` (`user_phone_number` ASC) VISIBLE);

desc user_signup;
select * from user_signup;
truncate table user_signup;

