CREATE TABLE `findings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`scan_target_id` integer NOT NULL,
	`category` text NOT NULL,
	`severity` text NOT NULL,
	`confidence` text NOT NULL,
	`cve_id` text,
	`explanation` text,
	`suggested_fix` text,
	FOREIGN KEY (`scan_target_id`) REFERENCES `scan_targets`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `scan_targets` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`scan_id` integer NOT NULL,
	`url` text NOT NULL,
	`status` text NOT NULL,
	`status_code` integer,
	`response_headers` text,
	`response_time_ms` integer,
	`tls_version` text,
	`tls_cert_expires_at` integer,
	`redirect_location` text,
	`error` text,
	FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `scans` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`status` text NOT NULL,
	`urls` text NOT NULL,
	`user_agent` text,
	`error` text,
	`created_at` integer NOT NULL,
	`completed_at` integer
);
