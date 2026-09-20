CREATE TABLE `takeover_findings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`enumerated_host_id` integer NOT NULL,
	`cname_target` text NOT NULL,
	`provider` text,
	`severity` text NOT NULL,
	`confidence` text NOT NULL,
	`remediation` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`enumerated_host_id`) REFERENCES `enumerated_hosts`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `takeover_findings_host` ON `takeover_findings` (`enumerated_host_id`);