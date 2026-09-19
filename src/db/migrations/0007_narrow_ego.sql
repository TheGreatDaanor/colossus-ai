CREATE TABLE `programs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`passive_host_cap` integer,
	`active_host_cap` integer,
	`enumeration_error` text,
	`last_enumerated_at` integer,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `scope_entries` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`program_id` integer NOT NULL,
	`list` text NOT NULL,
	`pattern` text NOT NULL,
	`confirmed_at` integer,
	FOREIGN KEY (`program_id`) REFERENCES `programs`(`id`) ON UPDATE no action ON DELETE no action
);
