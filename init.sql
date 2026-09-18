-- Lab Chuong 4: shopdb init (chay bang sa / Password1)
CREATE DATABASE shopdb;
GO
USE shopdb;
GO
CREATE TABLE products (id INT PRIMARY KEY, name NVARCHAR(100), price INT);
INSERT INTO products VALUES (1,N'Ban phim',500000),(2,N'Chuot',250000),(3,N'Man hinh',3000000);
CREATE TABLE customers (id INT PRIMARY KEY, fullname NVARCHAR(100), cccd VARCHAR(20), balance BIGINT);
INSERT INTO customers VALUES (1,N'Nguyen Van A','037201099888',50000000),(2,N'Tran Thi B','038155777222',12000000);
GO
