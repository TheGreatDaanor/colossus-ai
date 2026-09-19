CREATE TABLE `enumerated_hosts` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`program_id` integer NOT NULL,
	`hostname` text NOT NULL,
	`source` text NOT NULL,
	`scope_status` text NOT NULL,
	`first_seen_at` integer NOT NULL,
	FOREIGN KEY (`program_id`) REFERENCES `programs`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `enumerated_hosts_program_hostname` ON `enumerated_hosts` (`program_id`,`hostname`);