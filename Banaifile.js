var outputFile="banai"
function clean(){
    fsRemove(outputFile)
}

function build(){
    sh('go build -o '+outputFile+' .')
}
function main(){
    build()
}

