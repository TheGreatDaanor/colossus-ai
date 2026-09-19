ALTER TABLE `scans` ADD `mode` text DEFAULT 'passive' NOT NULL;--> statement-breakpoint
ALTER TABLE `scans` ADD `confirm_authorized` integer;--> statement-breakpoint
ALTER TABLE `scans` ADD `authorization_note` text;