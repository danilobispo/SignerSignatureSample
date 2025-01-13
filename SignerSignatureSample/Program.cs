using Lacuna.Signer.Api;
using Lacuna.Signer.Api.Documents;
using Lacuna.Signer.Api.Signature;
using Lacuna.Signer.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;

namespace SignerSignatureSample {
    class Program {
        public static string Url { get; set; } = "https://signer-lac.azurewebsites.net";
        public static string apiKey = "Teste App|fd0bad85cd9f8645b3a57cf787867800a2172bc36c6646951088181413fb750c";
        public static SignerClient client = new SignerClient(Url, apiKey, Lacuna.RestClient.AuthTokenTypes.ApiKey);
        static async Task Main(string[] args) {
            
            // 1. Set the file to be signed and perform the upload
            using var inputFile = File.OpenRead("sample.pdf");
            var upload = await client.UploadFileAsync("Sample PDF.pdf", inputFile, "application/pdf");

            // 2. Create the participants (signer, observer, etc.) for the document
            var user = new Lacuna.Signer.Api.Users.ParticipantUserModel() {
                Name = "Mr Robot",
                Identifier = "16155907064",
                Email = "mr.robot@mailinator.com"
            };

            // 3. Create the document request with the respective file and flow actions
            var documentRequest = new CreateDocumentRequest() {
                Files = new List<FileUploadModel>()
                {
                    new FileUploadModel(upload) {
                        DisplayName = "Sample PDF"
                    }
                },
                FlowActions = new List<Lacuna.Signer.Api.FlowActions.FlowActionCreateModel>()
                {
                    new Lacuna.Signer.Api.FlowActions.FlowActionCreateModel() {
                        User = user,
                        Type = FlowActionType.Signer,
                    }
                },
                
            };

            // 4. Create the document
            var result = await client.CreateDocumentAsync(documentRequest);

            // 5. Get the document's ID
            var documentId = result.First().DocumentId;

            // 6. Get the document Action URL to perform a signature in a standalone page
            var actionUrl = await client.GetActionUrlAsync(documentId, new ActionUrlRequest() {
                EmailAddress = user.Email,
                Identifier = user.Identifier
            });


            // 7. Get the document status by it's id
            var details = await client.GetDocumentDetailsAsync(documentId);

            // 8. Check if the whole flow is NOT concluded
            if (!details.IsConcluded) {


                // 9. If needed, check the status of individual flow actions
                foreach (var flowAction in details.FlowActions) {
                    if (flowAction.Status == ActionStatus.Pending) {
                        // if it is pending, then this user must perform the signature
                        var execFolder = AppDomain.CurrentDomain.BaseDirectory;
                        Console.WriteLine($"Application is running in: {execFolder}");
                        string projectRootFolder = Directory.GetParent(Directory.GetParent(Directory.GetParent(Directory.GetParent(execFolder).FullName).FullName).FullName).FullName;
                        Console.WriteLine($"Project root (where Program.cs is likely located): {projectRootFolder}");

                        if (TryCheckPfxFile(projectRootFolder, flowAction.User.Identifier, out string errorMessage)) {
                            Console.WriteLine($"The file '{flowAction.User.Identifier}.pfx' was found in folder '{projectRootFolder}'.");
                            // if we found the .pfx, then we must perform a server-side signature
                            
                            await PerformServerSideSignature(Path.Combine(projectRootFolder, $"{flowAction.User.Identifier}.pfx"),  actionUrl.Url);

                        } else {
                            Console.WriteLine($"Error: {errorMessage}");
                        }
                    }
                }
            }


            
            
        }

        public static byte[] SignHash(X509Certificate2 certificate, byte[] toSignHash) {
            var key = certificate.GetRSAPrivateKey();

            return key.SignHash(toSignHash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static bool TryCheckPfxFile(string directoryPath, string userIdentifier, out string errorMessage) {
            // Build the .pfx file complete path
            string filePath = Path.Combine(directoryPath, $"{userIdentifier}.pfx");

            // Check if it exists
            if (!File.Exists(filePath)) {
                errorMessage = $"File '{userIdentifier}.pfx' was not found in folder '{directoryPath}'.";
                return false;
            }

            errorMessage = string.Empty; // Nenhum erro
            return true;
        }

        public static async Task PerformServerSideSignature(string pfxFilePath, string actionUrl) {
            // 1. Create the signature URL
            var signatureUrl = new Uri(actionUrl);
            var documentKey = signatureUrl.LocalPath.Replace("/document/key/", string.Empty).Replace("/sign", string.Empty);
            // 2. Define as ticket
            var ticket = HttpUtility.ParseQueryString(signatureUrl.Query)["ticket"];

            // 3. Retrieve the certificate
            var certificate = new X509Certificate2(pfxFilePath, "1234");

            // 4. Create the request object
            var request = new PublicStartSignatureRequest() {
                Ticket = ticket,
                Certificate = certificate.Export(X509ContentType.Cert)
            };

            // 5. Perform the public signature async operation
            try {
                
                var response = await client.StartPublicSignatureAsync(documentKey, request);
                // 6. Next, sign the hash returned from the previous operation
                var signature = SignHash(certificate, response.ToSignHash);

                // 7. Complete the signature
                var signatureResponse = await client.CompletePublicSignatureAsync(documentKey, new CompleteSignatureRequest() {
                    Token = response.Token,
                    Signature = signature
                });

                //8. Get the verification URL
                var verificationUrl = new Uri(new Uri(Url), $"/validate/{documentKey}");
                Console.WriteLine("Verification URL is:");
                Console.WriteLine($"\n{verificationUrl}\n");
                Console.WriteLine("Generate a QR code from the URL above");
            } catch (Exception e) {
                throw e;
            }

            
        }
    }
}
