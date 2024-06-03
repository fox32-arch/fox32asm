local process = require("@lune/process")
local serde = require("@lune/serde")
local fs = require("@lune/fs")

type CargoDependencies = { [string]: (number | {}) }
type CargoToml = {
    package: {
        build: string,
        version: string,
        name: string,
        edition: string,
    },
    ["build-dependencies"]: CargoDependencies,
    dependencies: CargoDependencies,
}

local function execute(dir: string, command: string, ...): ()
    local args = {...}
    print(`--------> {command} {table.concat(args, " ")}`)

    local child = process.spawn(command, args, {
        shell = true,
        stdio = "forward",
        cwd = dir
    })

    print()

    if not child.ok then
        process.exit(child.code)
    end
end

function main(): number
    execute(process.cwd, "just", "build", "--release")

    local cargoToml: CargoToml = serde.decode("toml", fs.readFile("Cargo.toml"))
    local fileExt: ".exe" | "" = if process.os == "windows" then ".exe" else ""
    local zipName = `{cargoToml.package.name}-{cargoToml.package.version}-{process.arch}-{process.os}.zip`
    local fileName = `fox32asm{fileExt}`
    local command = {}

    if process.os == "windows" then
        command = {
            "7z.exe",
            "a",
            "-tzip",
            zipName,
            fileName
        }
    elseif process.os == "linux" then
        command = {
            "zip", 
            zipName, 
            fileName
        }
    end
    
    execute(
        `{process.cwd}/target/release`,
        table.unpack(command)
    )
    
    return 0
end

return process.exit(main())