const PROTO_PATH = "D:\\projects\\market-parser-go\\rpc\\market.proto";
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const packageDefinition = protoLoader.loadSync(
    PROTO_PATH,
    {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true
    });
const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
// The protoDescriptor object has the full package hierarchy
const messageService = protoDescriptor.MessageService;


function ReceiveAccessory(call, callback) {
    console.log(call.request)

    callback(null, true);
}

const main = () => {
    const server = new grpc.Server();
    server.addService(messageService.MessageService.service, {
        SendAccessory: ReceiveAccessory,
    })

    server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
        console.info("Listening")
        server.start();
    })
}

main();