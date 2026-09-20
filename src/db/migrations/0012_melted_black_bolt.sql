ALTER TABLE `enumerated_hosts` ADD `last_scanned_at` integer;--> statement-breakpoint
ALTER TABLE `scan_targets` ADD `enumerated_host_id` integer REFERENCES enumerated_hosts(id);--> statement-breakpoint
ALTER TABLE `scans` ADD `program_id` integer REFERENCES programs(id);