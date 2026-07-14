# OBR Mod Updater 0.5.2 Beta

## What this tool is

OBR Mod Updater is a Windows tool for checking older Oblivion Remastered mods and preparing an updated candidate when the mod matches a conversion path the tool understands.

It is intentionally cautious. It looks at the mod first, checks the selected game installation and any required tools, then either creates a candidate or gives you a report explaining why it stopped. It does not force unsupported mods through a conversion.

This is a beta release. A completed conversion means the files passed the tool's structural checks; you still need to test the result in-game.

## What it does

- Reads ZIP, 7Z, single-volume RAR, and extracted mod folders.
- Checks a mod before changing anything.
- Finds or lets you select your Oblivion Remastered installation.
- Connects required tools and compatibility dependencies when a supported update path needs them.
- Creates the updated candidate in a separate output folder.
- Saves a report and a copyable activity log when a mod cannot be processed.

## Quick setup FAQ

### Do I need to extract the updater ZIP?

Yes. Extract the whole ZIP to a normal folder before opening `OBR Mod Updater.exe`.

### The updater cannot find my game. What do I do?

Use **Find game** first. If it does not find the installation, choose **Folder** under **Game installation** and select your Oblivion Remastered game folder yourself.

### Where do I put UE4SS or TesSyncMapInjector?

Do not copy them into the updater folder at random.

If the updater says one is required, open **Dependencies & Runtime Tools** and use **Add archives** or **Add folder** to select the original download archive or its extracted folder. The updater checks that it is the correct tool before using it.

The `Dependencies` folder beside the updater is only an optional place to keep those original downloads together. It is not where you install UE4SS into the game.

### I already have UE4SS installed. Do I need to download it again?

No. If it is installed in the expected game runtime location, the updater can detect it. Otherwise, point the updater at the archive or folder you already have with **Add archives** or **Add folder**.

### Do I always need UE4SS or other tools?

No. Only some supported update paths need extra runtime tools or a compatibility dependency. The preflight screen tells you exactly what is missing for the mod you selected.

### What do I choose for the output folder?

Pick an existing folder outside your game installation and outside the source mod. The updater writes the candidate and its reports there, so your original download stays untouched.

### What happens when I select Analyze & update?

The tool runs preflight first. If every required check passes, it continues and writes a candidate to your output folder. If a check fails, it stops safely and gives you a report instead.

### Does the tool install the converted mod for me?

No. Install the candidate with your usual mod manager or place the complete generated container set in your normal mod location. Keep every file from the generated set together and remove any older copy of the same mod before testing.

### What is Fix installed modlist?

That is a separate, high-risk option for eligible mods that are already installed. It makes verified backups before replacing files, but you should still use it only when you understand that it may affect your installed mods. Keep the backup folder until you have tested everything.

### What should I send if something fails?

Use **Copy log**, then include the copied log, the generated JSON report, your game version, and a short description of what happened. Do not share personal file paths.

## Before you use it

Keep your original mod archive. Close the game before the updater needs to install or validate runtime tools. Test every generated candidate in-game, including its model, textures, materials, animations, collision, and physics where relevant.

## Download

Download the `OBR-Mod-Updater-v0.5.2-windows-x64.zip` release file, extract it, and start with `README.txt` inside the ZIP.