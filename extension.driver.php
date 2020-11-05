<?php

declare(strict_types=1);

/*
 * This file is part of the "Password Field for Symphony CMS" Extension repository.
 *
 * Copyright 2020 Alannah Kearney
 *
 * For the full copyright and license information, please view the LICENCE
 * file that was distributed with this source code.
 */

require_once realpath(__DIR__.'/vendor/autoload.php');

class Extension_PasswordField extends Extension
{
    public function uninstall()
    {
        Symphony::Database()->query('DROP TABLE `tbl_fields_password`');
    }

    public function install()
    {
        return Symphony::Database()
            ->query("CREATE TABLE IF NOT EXISTS `tbl_fields_password` (
              `id` int(11) unsigned NOT NULL auto_increment,
              `field_id` int(11) unsigned NOT NULL,
              `length` tinyint(2) NOT NULL,
              `strength` enum('weak', 'good', 'strong') NOT NULL,
              PRIMARY KEY  (`id`),
              UNIQUE KEY `field_id` (`field_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;");
    }
}
