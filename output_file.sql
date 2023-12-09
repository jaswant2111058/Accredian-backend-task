-- MySQL dump 10.13  Distrib 8.0.33, for Win64 (x86_64)
--
-- Host: localhost    Database: accrediandb
-- ------------------------------------------------------
-- Server version	8.0.33

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `userdetail`
--

DROP TABLE IF EXISTS `userdetail`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `userdetail` (
  `_id` varchar(150) NOT NULL,
  `userName` varchar(45) NOT NULL,
  `email` varchar(45) NOT NULL,
  `password` varchar(150) NOT NULL,
  PRIMARY KEY (`_id`),
  UNIQUE KEY `_id_UNIQUE` (`_id`),
  UNIQUE KEY `userName_UNIQUE` (`userName`),
  UNIQUE KEY `email_UNIQUE` (`email`),
  UNIQUE KEY `password_UNIQUE` (`password`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `userdetail`
--

LOCK TABLES `userdetail` WRITE;
/*!40000 ALTER TABLE `userdetail` DISABLE KEYS */;
INSERT INTO `userdetail` VALUES ('498db0ac-af5e-457b-94ec-8b13b98f27bb','Jassi3','jassimorya@gmail.com','$2a$12$y0p0WtfA6DRve/4SK3vDM.6rxO7JPSNfbMvLq/S/LI9eQ6ZS4LYnW'),('4e504963-aec5-44c7-8359-ae410ccb56c2','Jassi74','jassimojvghjkry1a@gmail.com','$2a$12$C.wPc37odcPeqAtZ2Pc4Su05klmZUGNUHC41t/qnlzGpdhq/Hg3fW'),('9be1ad9c-011f-4d28-bf29-6c2788f7e46c','Jassi174','jassimojvghjkbry1a@gmail.com','$2a$12$jKRn6q/jaLb2nNt4PtlX9efw2OGAvH4MRvsJ5aoEiohb5aHkpx1Va'),('a42c06ea-c18c-4cdb-aaf9-bfc8c893a827','manisha','manishakushwaha15102006@gmail.com','$2a$12$67lcAZCiFsfwjASYuvit1eEXJ.594NFUJZvOUnwCXyckFHcwXAGnG'),('da990d8d-7654-43de-8981-1345aa07abfc','Jassi2','jkushwaha1010@gmail.com','$2a$12$QaJCCZpQsY4bdMno1u11meF6zfiCNAr9QFbapaEf/N5Dq1jNV0d.K'),('db4ab703-0966-421f-a881-0df96972015d','Jassi44','jassimojvghjkrya@gmail.com','$2a$12$1u0KumlOVpiLnjENLfPcZeSutk4jSQKifnCwLVGEoCTA3yx0.gN42'),('e4049db7-6254-4313-a195-189e66d27d53','Jassi4','jassimojkrya@gmail.com','$2a$12$OcHnBmXSkF4AZEXZQYNYUuumao/i8EbwUO1SP0kt4xHCQdzro7ENi'),('fec53180-f7a6-48c1-9859-1e31e6b863e8','Jassi','jkstar0123@gmail.com','$2a$12$Y8/F0CbotqJb/NHFgO2UzezVMBm.qToRc3u2.TgSV2JJ8rKFi5tiW');
/*!40000 ALTER TABLE `userdetail` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-12-10  0:02:55
