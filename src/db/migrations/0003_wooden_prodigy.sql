ALTER TABLE `scan_targets` ADD `discovered_from` integer REFERENCES scan_targets(id);
