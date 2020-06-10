using System;
using System.Collections.Generic;
//using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using LibUA.Security.Cryptography;
using LibUA.Security.Cryptography.X509Certificates;
using LibUA;
using LibUA.Core;
using LibUA.Server;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
//using System.Text;

namespace TestServer
{
    /// <summary>
    /// This Class implement the UA-Server-Application
    /// </summary>
    class DemoApplication : LibUA.Server.Application
    {
        ApplicationDescription uaAppDesc;

        NodeObject ItemsRoot;
        NodeVariable[] TrendNodes;

        X509Certificate2 appCertificate = null;
        RSACryptoServiceProvider cryptPrivateKey = null;

        public override X509Certificate2 ApplicationCertificate
        {
            get { return this.appCertificate; }
        }

        public override RSACryptoServiceProvider ApplicationPrivateKey
        {
            get { return cryptPrivateKey; }
        }


        private void printCertInfo()
        {
            if (this.appCertificate != null)
            {
                Console.WriteLine("Certficate loaded:");
                Console.WriteLine("##################");
                Console.WriteLine("Subject: " + this.appCertificate.Subject);
                Console.WriteLine("Serialnumber: " + this.appCertificate.SerialNumber);
                Console.WriteLine("Issuer: " + this.appCertificate.Issuer);
                Console.WriteLine("Valid from: " + this.appCertificate.NotBefore.ToString());
                Console.WriteLine("Valid to: " + this.appCertificate.NotAfter.ToString());
                Console.WriteLine("");
            }
        }

        #region constructor
        public DemoApplication()
        {
            //LoadCertificateAndPrivatekeyFromFile();
            LoadCertficateAndPrivateKeyFromCertStore("1.3.6.1.5.5.7.3.1", "CN=OLPDO-CA, DC=olplastik, DC=de");
            if (this.appCertificate == null)  //Valid certificate could not be found...
            {
                throw (new OperationCanceledException("Unable to load valid certificate from certificates store. Aborting.")); //Raise exception which will cause the program to abort
            }
            else
            {
                this.printCertInfo();
            }

            uaAppDesc = new ApplicationDescription(
                "url:qs:DemoApplication", "http://quantensystems.com/",
                new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Server,
                null, null, null);

            ItemsRoot = new NodeObject(new NodeId(2, 0), new QualifiedName("Items"), new LocalizedText("Items"), new LocalizedText("Items"), 0, 0, 0);

            // Objects organizes Items
            AddressSpaceTable[new NodeId(UAConst.ObjectsFolder)].References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), new NodeId(2, 0), false));
            ItemsRoot.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), new NodeId(UAConst.ObjectsFolder), true));
            AddressSpaceTable.TryAdd(ItemsRoot.Id, ItemsRoot);

            TrendNodes = new NodeVariable[1000];
            var nodeTypeFloat = new NodeId(0, 10);
            for (int i = 0; i < TrendNodes.Length; i++)
            {
                var id = string.Format("Trend {0}", (1 + i).ToString("D6"));
                TrendNodes[i] = new NodeVariable(new NodeId(2, (uint)(1 + i)), new QualifiedName(id),
                    new LocalizedText(id), new LocalizedText(id), 0, 0,
                    AccessLevel.CurrentRead | AccessLevel.HistoryRead,
                    AccessLevel.CurrentRead | AccessLevel.HistoryRead, 0, true, nodeTypeFloat);

                ItemsRoot.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), TrendNodes[i].Id, false));
                TrendNodes[i].References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), ItemsRoot.Id, true));
                AddressSpaceTable.TryAdd(TrendNodes[i].Id, TrendNodes[i]);
            }
        }
        #endregion

        #region methods
        public override object SessionCreate(SessionCreationInfo sessionInfo)
        {
            // Create and return a session object with sessionInfo

            return null;
        }

        public override bool SessionValidateClientApplication(object session, ApplicationDescription clientApplicationDescription, byte[] clientCertificate, string sessionName)
        {
            // Update your session object with the client's UA application description
            // Return true to allow the client, false to reject

            return true;
        }

        public override void SessionRelease(object session)
        {
        }

        public override bool SessionValidateClientUser(object session, object userIdentityToken)
        {
            if (userIdentityToken is UserIdentityAnonymousToken)
            {
                return true;
            }
            else if (userIdentityToken is UserIdentityUsernameToken)
            {
                var username = (userIdentityToken as UserIdentityUsernameToken).Username;
                var password = (new UTF8Encoding()).GetString((userIdentityToken as UserIdentityUsernameToken).PasswordHash);

                return true;
            }

            throw new Exception("Unhandled user identity token type");
            return base.SessionValidateClientUser(session, userIdentityToken);
        }

        public override IList<EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
        {
            var certStr = ApplicationCertificate.Export(X509ContentType.Cert);

            var epNoSecurity = new EndpointDescription(
                endpointUrlHint, uaAppDesc, null,
                MessageSecurityMode.None, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None],
                new UserTokenPolicy[]
                {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                }, Types.TransportProfileBinary, 0);

            var epSignBasic128Rsa15 = new EndpointDescription(
                endpointUrlHint, uaAppDesc, certStr,
                MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15],
                new UserTokenPolicy[]
                {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15]),
                }, Types.TransportProfileBinary, 0);

            var epSignBasic256 = new EndpointDescription(
                endpointUrlHint, uaAppDesc, certStr,
                MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256],
                new UserTokenPolicy[]
                {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256]),
                }, Types.TransportProfileBinary, 0);

            var epSignBasic256Sha256 = new EndpointDescription(
                endpointUrlHint, uaAppDesc, certStr,
                MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                new UserTokenPolicy[]
                {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            var epSignEncryptBasic128Rsa15 = new EndpointDescription(
                endpointUrlHint, uaAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15],
                new UserTokenPolicy[]
                {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15]),
                }, Types.TransportProfileBinary, 0);

            var epSignEncryptBasic256 = new EndpointDescription(
                endpointUrlHint, uaAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256],
                new UserTokenPolicy[]
                {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256]),
                }, Types.TransportProfileBinary, 0);

            var epSignEncryptBasic256Sha256 = new EndpointDescription(
                endpointUrlHint, uaAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                new UserTokenPolicy[]
                {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                }, Types.TransportProfileBinary, 0);

            return new EndpointDescription[]
            {
                    epNoSecurity,
                    epSignBasic256Sha256, epSignEncryptBasic256Sha256,
                    epSignBasic128Rsa15, epSignEncryptBasic128Rsa15,
                    epSignBasic256, epSignEncryptBasic256
            };
        }

        public override ApplicationDescription GetApplicationDescription(string endpointUrlHint)
        {
            return uaAppDesc;
        }

        protected override DataValue HandleReadRequestInternal(NodeId id)
        {
            Node node = null;
            if (id.NamespaceIndex == 2 &&
                AddressSpaceTable.TryGetValue(id, out node))
            {
                return new DataValue(3.14159265, StatusCode.Good, DateTime.Now);
            }

            return base.HandleReadRequestInternal(id);
        }

        List<DataValue> testHistoryPoints = null;
        public override UInt32 HandleHistoryReadRequest(object session, object readDetails, HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<DataValue> results, ref int? offsetContinueFit)
        {
            if (testHistoryPoints == null)
            {
                testHistoryPoints = new List<DataValue>();

                var dt = new DateTime(2015, 12, 1);
                for (int i = 0; i < 100000; i++)
                {
                    testHistoryPoints.Add(new DataValue(Math.Sin(i * 0.3) + Math.Cos(i * 0.17) * 0.5 + Math.Sin(i * 0.087) * 0.25, StatusCode.Good, dt));
                    dt = dt.AddHours(1);
                }
            }

            int startOffset = continuationPoint.IsValid ? continuationPoint.Offset : 0;
            if (readDetails is ReadRawModifiedDetails)
            {
                var rd = readDetails as ReadRawModifiedDetails;
                for (int i = 0; i < 100000; i++)
                {
                    var p = testHistoryPoints[i];
                    if (p.SourceTimestamp >= rd.StartTime &&
                        p.SourceTimestamp < rd.EndTime)
                    {
                        // Skip startOffset points
                        if (startOffset > 0)
                        {
                            startOffset--;
                            continue;
                        }

                        results.Add(p);
                    }
                }

                return (UInt32)StatusCode.Good;
            }

            return (UInt32)StatusCode.BadHistoryOperationUnsupported;
        }

        public override UInt32 HandleHistoryEventReadRequest(object session, object readDetails, HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<object[]> results)
        {
            if (readDetails is ReadEventDetails)
            {
                var rd = readDetails as ReadEventDetails;

                var dt = rd.StartTime;
                for (int i = 0; i < 5; i++)
                {
                    var ev = GenerateSampleAlarmEvent(dt);
                    results.Add(NetDispatcher.MatchFilterClauses(rd.SelectClauses, ev));
                    dt = dt.AddMinutes(1);
                }
                return (UInt32)StatusCode.Good;
            }

            return (UInt32)StatusCode.BadHistoryOperationUnsupported;
        }

        protected int rowCount = 1;
        protected Random rnd = new Random();

        // These numbers are allowed to wrap in case of overflow
        // These are usually used by the client to match events
        protected UInt64 nextEventId = 1;

        EventNotification GenerateSampleAlarmEvent(DateTime eventTime)
        {
            return new EventNotification(new EventNotification.Field[]
            {
					// During publishing, operand BrowsePaths are matched
					// against UA select clauses from the subscriber.
					// The operands shown here are the most common requested (90% of cases).
					// Types match operand BrowsePath, do not change them and remember
					// casting when passing into a variant.

					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("EventId") }
                        ),
                        Value = nextEventId
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("EventType") }
                        ),
                        Value = new NodeId(UAConst.ExclusiveLevelAlarmType)
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("SourceName") }
                        ),
                        Value = "Source name"
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("Time") }
                        ),
                        Value = eventTime,
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("Message") }
                        ),
                        Value = new LocalizedText("Event message")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("Severity") }
                        ),
						// Severity is 0 to 1000
						Value = (UInt16)(rnd.Next() % 1000)
                    },
					// ActiveState object is a name, Id gives the value specified by the name
					// The names do not mean anything (just display text), but Id is important
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("ActiveState") }
                        ),
                        Value = new LocalizedText("Active")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
							// Represents ActiveState.Id
							new[] { new QualifiedName("ActiveState"), new QualifiedName("Id") }
                        ),
						// Inactive specifies false, Active specifies true
						Value = true
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("ActiveState"), new QualifiedName("EffectiveDisplayName") }
                        ),
                        Value = new LocalizedText("Alarm active")
                    },
					// Same rules for AckedState
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("AckedState") }
                        ),
                        Value = new LocalizedText("Acknowledged")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
							// Represents AckedState.Id
							new[] { new QualifiedName("AckedState"), new QualifiedName("Id") }
                        ),
						// Inactive specifies false, Active specifies true
						Value = true,
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("Retain") }
                        ),
                        Value = true
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] { new QualifiedName("ConditionName") }
                        ),
                        Value = "Sample alarm"
                    },
					// Necessary field for alarms
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            NodeId.Zero, new[] { new QualifiedName("ConditionType") },
                            NodeAttribute.NodeId, null
                        ),
                        Value = NodeId.Zero
                    },
            });
        }

        public void PlayRow()
        {
            //Console.WriteLine("Play row {0}", rowCount);

            foreach (var node in TrendNodes)
            {
                var dv = new DataValue((float)(rowCount + 0.1 * rnd.NextDouble()), StatusCode.Good, DateTime.Now);
                MonitorNotifyDataChange(node.Id, dv);
            }

            ++rowCount;

            var eventTime = DateTime.UtcNow;
            var ev = GenerateSampleAlarmEvent(eventTime);
            // MonitorNotifyEvent(new NodeId(UAConst.Server), ev);

            nextEventId++;
        }

        #region x509
        /// <summary>
        /// Will try to load a certificate form the os's certificate store
        /// </summary>
        /// <param name="usageOID">Application-OID (Default=Computeridentification)</param>
        /// <param name="issuer">Name of the issueing CA</param>
        private void LoadCertficateAndPrivateKeyFromCertStore(String usageOID = "1.3.6.1.5.5.7.3.1"/*computer-authentication by default*/, String issuer = "DEMO-CA")
        {
            this.appCertificate = new X509Certificate2();

            X509Store SystemStore = new X509Store(StoreLocation.LocalMachine); // Set the local certificate store as local machine
            SystemStore.Open(OpenFlags.ReadOnly); // Oen the stroe in ReadOnly-Mode                
            X509Certificate2Collection allcerts = SystemStore.Certificates.Find(X509FindType.FindByApplicationPolicy, usageOID, true); // Find all valid certificates
            if (allcerts.Count > 0)
            { // At least one certificate was found
                foreach (X509Certificate2 temp in allcerts)
                {
                    if (temp.IssuerName.Name.Equals(issuer) && temp.Verify())
                    { // if the cert has been issued by the correct CA and is valid
                        this.appCertificate = temp; // use that cert
                        return;
                    }
                }
                //cer = allcerts[0]; //use the first certificate found. May be adjust/enhance this later
            }
            this.appCertificate = null; // Set the certificate to null if none was found.
        }

        /// <summary>
        /// This will load Certificate and private key for the server from a file. If File doesn't exist a dummy file will be created.
        /// </summary>
        private void LoadCertificateAndPrivatekeyFromFile(String certfile = "ServerCert.der", String privkeyfile = "ServerKey.pem")
        {
            try
            {
                // Try to load existing (public key) and associated private key
                this.appCertificate = new X509Certificate2(certfile);
                this.cryptPrivateKey = new RSACryptoServiceProvider();

                var rsaPrivParams = UASecurity.ImportRSAPrivateKey(File.ReadAllText(privkeyfile));
                this.cryptPrivateKey.ImportParameters(rsaPrivParams);
            }
            catch
            {
                // If existing certificate could not be loaded:
                // Make a new certificate (public key) and associated private key
                var dn = new X500DistinguishedName("CN=Client certificate;OU=Demo organization", X500DistinguishedNameFlags.UseSemicolons);

                var keyCreationParameters = new CngKeyCreationParameters()
                {
                    KeyUsage = CngKeyUsages.AllUsages,
                    KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport
                };

                keyCreationParameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(1024), CngPropertyOptions.None));
                var cngKey = CngKey.Create(CngAlgorithm2.Rsa, "KeyName", keyCreationParameters);

                var certParams = new X509CertificateCreationParameters(dn)
                {
                    StartTime = DateTime.Now,
                    EndTime = DateTime.Now.AddYears(10),
                    SignatureAlgorithm = X509CertificateSignatureAlgorithm.RsaSha1,
                    TakeOwnershipOfKey = true
                };

                appCertificate = cngKey.CreateSelfSignedCertificate(certParams);

                var certPrivateCNG = new RSACng(appCertificate.GetCngPrivateKey());
                var certPrivateParams = certPrivateCNG.ExportParameters(true);

                File.WriteAllText(certfile, UASecurity.ExportPEM(appCertificate));
                File.WriteAllText(privkeyfile, UASecurity.ExportRSAPrivateKey(certPrivateParams));

                cryptPrivateKey = new RSACryptoServiceProvider();
                cryptPrivateKey.ImportParameters(certPrivateParams);
            }
        }
        #endregion
        #endregion
    }
}
