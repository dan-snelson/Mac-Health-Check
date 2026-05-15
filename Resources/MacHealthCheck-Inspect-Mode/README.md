# Mac Health Check 4
## [Inspect Mode](https://swiftdialog.app/advanced/inspect-mode/)

> The SwiftDialog Inspect Mode is a new built-in feature that enables real-time monitoring within the macOS filesystem. It tracks filesystem status (utilizing Apple’s FSEvents API) while monitoring application installations and inspecting cache folders, files, and plist content to visualize compliance checks. This feature is specifically designed for use during device enrollment, software deployment, and compliance auditing, providing end users with clear visibility into their compliance status.

While version `4.0.0` of Mac Health Check was _initially_ focused on **enterprise** reporting (by uploading `JSON` to a data warehouse), it dawned on me one morning that client-side `JSON` could be used to leverage Henry's sweet, sweet Inspect Mode for end-user reporting.

## Screenshots

<table>
	<tr>
		<td><a href="Screenshot%202026-05-15%20at%2010.42.57%E2%80%AFAM.png"><img src="Screenshot%202026-05-15%20at%2010.42.57%E2%80%AFAM.png" alt="Computer Needs Attention" width="320"></a>Computer Needs Attention</td>
		<td><a href="Screenshot%202026-05-15%20at%2010.43.10%E2%80%AFAM.png"><img src="Screenshot%202026-05-15%20at%2010.43.10%E2%80%AFAM.png" alt="Results Overview" width="320"></a>Results Overview</td>
		<td><a href="Screenshot%202026-05-15%20at%2010.43.22%E2%80%AFAM.png"><img src="Screenshot%202026-05-15%20at%2010.43.22%E2%80%AFAM.png" alt="Remediation Guide" width="320"></a>Remediation Guide</td>
	</tr>
	<tr>
		<td><a href="Screenshot%202026-05-15%20at%2010.43.33%E2%80%AFAM.png"><img src="Screenshot%202026-05-15%20at%2010.43.33%E2%80%AFAM.png" alt="Maintenance Status" width="320"></a>Maintenance Status</td>
		<td><a href="Screenshot%202026-05-15%20at%2010.43.41%E2%80%AFAM.png"><img src="Screenshot%202026-05-15%20at%2010.43.41%E2%80%AFAM.png" alt="Maintenance Detail" width="320"></a>Maintenance Detail</td>
		<td><a href="Screenshot%202026-05-15%20at%2010.44.11%E2%80%AFAM.png"><img src="Screenshot%202026-05-15%20at%2010.44.11%E2%80%AFAM.png" alt="Next Steps" width="320"></a>Next Steps</td>
	</tr>
</table>
