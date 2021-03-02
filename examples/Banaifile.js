function printOut() {
    println("Printed from function PrintOut")
}

function localScripts() {
    //---------- local script
    var opt = {
        shell: "",
        in: "",
        ins: [],
        env: ["ENV1=VAL1", "ENV2=VAL2"],
        timeout: 0,
        secretId: ""
    }
    println("DESKTOP_SESSION value is: ", env['DESKTOP_SESSION'])
    res = sh('env', opt)
    var lines = res.out.split("\n")
    for (var s = 0; s < lines.length; s++) {
        println(lines[s])
    }

    res = shScript("examples/script.sh")
    var lines = res.out.split("\n")
    for (var s = 0; s < lines.length; s++) {
        println(lines[s])
    }

    println(pwd())
    try {
        cd("asdasd")
    } catch (err) {
        println("At catch")
        println("Failed to change directoy", err)
    }

    try {
        cd("dump")
    } catch (err) {
        println("At catch")
        println("Failed to change directoy", err)
    }

    println(pwd())
    cd("..")
    println(pwd())

}


function remoteCommands() {
    //------------ remote script
    var sshConf = {
        address: '54.86.130.77:22',
        user: 'ec2-user',
        privateKeyFile: '/home/sagi/.ssh/foodsager.pem'
    }
    println("copy file to remote")
    shUpload(sshConf, "examples/testfile.js", "b.js")


    println("Running ls on remote")
    res = rsh(sshConf, 'ls -l')
    println('stdout: ', res.out)

    rsh(sshConf, 'rm b.js')
    println(rsh(sshConf, 'ls -l').out)
}

function fileExamples() {
    var finalFile = "dump/my-text12.txt"
    fsRemove(finalFile)
    var fileContentBin = fsRead("examples/script.sh")
    println("Reading file:\n", fileContentBin)
    var fileContentText = fsRead("examples/script.sh")

    fsWrite("dump/bin.txt", fileContentText)

    println("Create dir")
    fsCreateDir("dump/mydir")
    fsWrite("dump/mydir/text.txt", "asdasdasd")
    fsCopy("dump/mydir/text.txt", "dump/my-text2.txt")
    fsMove("dump/my-text2.txt", finalFile)
    println("Delete dir")
    fsRemoveDir("dump/mydir")

    var res = fsSplit(finalFile)
    println("Path", finalFile, "Parts are:", JSON.stringify(res))

    println("Join back ", fsJoin(res.folder, res.file))

    res = fsList("dump")
    println("Content of dump:", res)

    res = fsList("dump", "f")
    println("Only files in dump:", res)

    res = fsList("dump", "d")
    println("Only sub directories in dump:", res)

    println("Absolute path of ", finalFile, "is", fsAbs(finalFile))

    println(JSON.stringify(fsItemInfo("examples")))

    println(JSON.stringify(fsItemInfo("examples/script.sh")))
}

function zipExample() {
    println("Ziping dump")
    println("File zipped: ", arZip("dump-out/dump.zip", "dump"))
    println("Unzipping....")
    println("Files unzipped: ", arUnzip("dump-out/dump.zip", "dump-out"))
}

function dockerExample() {
    println(JSON.stringify(dkrList()))
    dkrStop("2b7d9e6c9a89e3ad86600ad36c823f8e13b9d36e637cbdcb676371c6c2ce5f75")

}

function hashExample() {
    println("MD5 of banai file: ", hashMd5File('examples/testfile.js'))
    println("MD5 of text: ", hashMd5Text('line123'))
    println("SHA1 of banai file: ", hashSha1File('examples/testfile.js'))
    println("SHA1 of text: ", hashSha1Text('line123'))
    println("SHA256 of banai file: ", hashSha256File('examples/testfile.js'))
    println("SHA256 of text: ", hashSha256Text('line123'))
}

function testREST() {
    var opt = {
        contentType: "json",
        header: { "Banai-Header": "Post json" }
    }

    var res = httpPost("https://ptsv2.com/t/dg1g3-1614349524/post", JSON.stringify({ "fld": "Sagi" }), opt)
    println("Status ", res.status)
    println("Content=", res.body)

    res = httpPostForm("https://ptsv2.com/t/dg1g3-1614349524/post", { "fld1": "sagi" }, { "file": "examples/script.sh" })
    println("Status ", res.status)
    println("Content=", res.body)

    res = httpPostForm("https://ptsv2.com/t/dg1g3-1614349524/post", { "fld2": "sagi2" })
    println("Status ", res.status)
    println("Content=", res.body)


}

function testSecrets() {
    println("Text secret",getTextSecret("secret 1"))
    println("SSH secret", JSON.stringify(getSSHSecret("secret 2")))
    println("User passowrd", JSON.stringify(getUserPassSecret("secret 3")))

}

function main() {
    // localScripts()
    // remoteCommands()
    // fileExamples()
    // zipExample()
    // hashExample()
    // testREST()
    // testSecrets()
}
