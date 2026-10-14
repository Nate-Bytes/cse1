DROP DATABASE IF EXISTS cse1_inventory;
CREATE DATABASE cse1_inventory;
USE cse1_inventory;

CREATE TABLE USERS (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Admin', 'Manager', 'Staff') NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    totp_secret TEXT DEFAULT NULL,
    totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
    totp_last_used BIGINT UNSIGNED DEFAULT NULL,
    totp_failed_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    totp_locked_until DATETIME DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE SUPPLIERS (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    contact_person VARCHAR(100) DEFAULT NULL,
    phone VARCHAR(30) DEFAULT NULL,
    email VARCHAR(100) DEFAULT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE PRODUCTS (
    id INT AUTO_INCREMENT PRIMARY KEY,
    supplier_id INT NOT NULL,
    name VARCHAR(150) NOT NULL,
    sku VARCHAR(100) NOT NULL UNIQUE,
    quantity INT NOT NULL DEFAULT 0,
    reorder_level INT NOT NULL DEFAULT 5,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_products_supplier FOREIGN KEY (supplier_id) REFERENCES SUPPLIERS(id)
);

CREATE TABLE TRANSACTION_HISTORY (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_id INT NOT NULL,
    type ENUM('IN', 'OUT') NOT NULL,
    quantity INT NOT NULL,
    before_quantity INT NOT NULL,
    after_quantity INT NOT NULL,
    notes VARCHAR(255) DEFAULT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_history_product FOREIGN KEY (product_id) REFERENCES PRODUCTS(id),
    CONSTRAINT fk_history_user FOREIGN KEY (user_id) REFERENCES USERS(id)
);

INSERT INTO USERS (name, email, password_hash, role, is_active)
VALUES
('Printworks Admin', 'admin@demo.com', '$2y$10$49N9VstxKBBsjZ79e3rS9OWjXFNseFa8QXXHMk7gSjSlRe0zPKpOS', 'Admin', 1),
('Production Manager', 'manager@demo.com', '$2y$10$qC/RzODphnsqgfesCdRgy.LcCDCufeR5MOrVbeGE.5.ftfis8.lpu', 'Manager', 1),
('Press Operator', 'staff@demo.com', '$2y$10$.RLWBDUPko5xi64/Aoez0urWoieX3705XfoEoBgMCFZ.m8oMAz4dO', 'Staff', 1);

INSERT INTO SUPPLIERS (name, contact_person, phone, email, is_active)
VALUES
('PrintMate Supplies', 'Alicia Reyes', '0917-110-2201', 'alicia@printmate.com', 1),
('InkPro Trading', 'Marlon Dela Cruz', '0917-220-3302', 'sales@inkpro.ph', 1),
('PaperSource Direct', 'Cecile Ramos', '0917-330-4403', 'orders@papersource.ph', 1);

INSERT INTO PRODUCTS (supplier_id, name, sku, quantity, reorder_level, is_active)
VALUES
(1, 'Offset Ink Black 5L', 'INK-BLK-5L', 18, 8, 1),
(1, 'Printing Plate 18x24', 'PLATE-18X24', 12, 6, 1),
(2, 'A3 Glossy Paper 500s', 'PAPER-A3-500', 7, 10, 1),
(2, 'Cyan Toner Cartridge', 'TONER-CYAN', 0, 6, 1),
(3, 'Binding Wire 100pcs', 'BIND-WIRE-100', 22, 12, 1),
(3, 'LAMINATION Film 50m', 'LAM-50M', 4, 7, 1);

INSERT INTO TRANSACTION_HISTORY (product_id, type, quantity, before_quantity, after_quantity, notes, user_id)
VALUES
(1, 'IN', 12, 6, 18, 'New ink delivery for weekly print run', 2),
(2, 'IN', 8, 4, 12, 'Plate restock from supplier', 2),
(3, 'OUT', 3, 10, 7, 'Stock issued for poster batch', 3),
(5, 'IN', 15, 7, 22, 'Supplied binding materials for packaging jobs', 2),
(6, 'OUT', 2, 6, 4, 'Used for finishing job order', 3);
