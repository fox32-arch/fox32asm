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
    execute(process.cwd, "/bin/just", "build", "--release")

    local cargoToml: CargoToml = serde.decode("toml", fs.readFile("Cargo.toml"))
    local fileExt: "exe" | "" = if process.os == "windows" then "exe" else ""
    execute(`{process.cwd}/target/release`, "zip", `{cargoToml.package.name}-{cargoToml.package.version}-{process.arch}-{process.os}.zip`, `fox32asm{fileExt}`)
    
    return 0
end

return process.exit(main())