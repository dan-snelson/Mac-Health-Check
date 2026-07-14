# Mac Health Check 4.0.0

## [Inspect Mode](https://swiftdialog.app/advanced/inspect-mode/)

> The SwiftDialog Inspect Mode is a new built-in feature that enables real-time monitoring within the macOS filesystem. It tracks filesystem status (utilizing Apple’s FSEvents API) while monitoring application installations and inspecting cache folders, files, and plist content to visualize compliance checks. This feature is specifically designed for use during device enrollment, software deployment, and compliance auditing, providing end users with clear visibility into their compliance status.

While version `4.0.0` of Mac Health Check was _initially_ focused on **enterprise** reporting (by uploading `JSON` to a data warehouse), it dawned on me one morning that client-side `JSON` could be used to leverage Henry's sweet, sweet Inspect Mode for end-user reporting.

Version `4.0.0` keeps the report hard-coded to Preset 6 and targets swiftDialog `3.1.0.4994`, the RC2 build containing PR #684. Generated bento grids use the schema-supported `12`-point gap, and the Overview uses a status-aware `highlight` block that RC2 renders as centered onboarding copy. PR #684 also tolerates quoted scalar values from MDM templates; Mac Health Check continues to generate native JSON numbers and booleans. No form controls are included, so the report remains read-only.

## Screenshots

<table>
	<tr>
		<td><a href="Screenshot%202026-06-23%20at%205.14.51%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.14.51%E2%80%AFPM.png" alt="Main Dialog" width="320"></a>Main Dialog</td>
		<td><a href="Screenshot%202026-06-23%20at%205.15.03%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.15.03%E2%80%AFPM.png" alt="Results Overview" width="320"></a>Results Overview</td>
		<td><a href="Screenshot%202026-06-23%20at%205.15.58%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.15.58%E2%80%AFPM.png" alt="Security Status" width="320"></a>Security Status</td>
		<td><a href="Screenshot%202026-06-23%20at%205.16.02%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.16.02%E2%80%AFPM.png" alt="AirDrop Detail Sheet" width="320"></a>AirDrop Detail Sheet</td>
		<td><a href="Screenshot%202026-06-23%20at%205.16.19%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.16.19%E2%80%AFPM.png" alt="Bluetooth Sharing Detail Sheet" width="320"></a>Bluetooth Sharing Detail Sheet</td>
	</tr>
	<tr>
		<td><a href="Screenshot%202026-06-23%20at%205.16.31%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.16.31%E2%80%AFPM.png" alt="Maintenance Status" width="320"></a>Maintenance Status</td>
		<td><a href="Screenshot%202026-06-23%20at%205.16.36%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.16.36%E2%80%AFPM.png" alt="App Auto-Patch Detail Sheet" width="320"></a>App Auto-Patch Detail Sheet</td>
		<td><a href="Screenshot%202026-06-23%20at%205.16.49%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.16.49%E2%80%AFPM.png" alt="Applications Status" width="320"></a>Applications Status</td>
		<td><a href="Screenshot%202026-06-23%20at%205.16.57%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.16.57%E2%80%AFPM.png" alt="Homebrew Status Detail Sheet" width="320"></a>Homebrew Status Detail Sheet</td>
		<td><a href="Screenshot%202026-06-23%20at%205.17.56%E2%80%AFPM.png"><img src="Screenshot%202026-06-23%20at%205.17.56%E2%80%AFPM.png" alt="Next Steps" width="320"></a>Next Steps</td>
	</tr>
</table>
