using Akka.Actor;
using Bhp.BhpExtensions;
using Bhp.BhpExtensions.CertificateSign;
using Bhp.BhpExtensions.RPC;
using Bhp.Consensus;
using Bhp.IO;
using Bhp.IO.Json;
using Bhp.Ledger;
using Bhp.Network.P2P;
using Bhp.Network.P2P.Payloads;
using Bhp.Persistence;
using Bhp.Persistence.LevelDB;
using Bhp.Plugins;
using Bhp.Services;
using Bhp.SmartContract;
using Bhp.VM;
using Bhp.Wallets;
using Bhp.Wallets.BRC6;
using Bhp.Wallets.SQLite;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ECCurve = Bhp.Cryptography.ECC.ECCurve;
using ECPoint = Bhp.Cryptography.ECC.ECPoint;

namespace Bhp.Shell
{
    internal class MainService : ConsoleServiceBase
    {
        private const string PeerStatePath = "peers.dat";

        private LevelDBStore store;
        private BhpSystem system;
        private WalletIndexer indexer;
        private System.Timers.Timer exportWalletTimer;

        protected override string Prompt => "bhp";
        public override string ServiceName => $"BHP-CLI V{Assembly.GetEntryAssembly().GetName().Version.ToString()}";

        private WalletIndexer GetIndexer()
        {
            if (indexer is null)
                indexer = new WalletIndexer(Settings.Default.Paths.Index);
            return indexer;
        }

        private static bool NoWallet()
        {
            if (Program.Wallet != null) return false;
            Console.WriteLine("You have to open the wallet first.");
            return true;
        }

        protected override bool OnCommand(string[] args)
        {
            if (Plugin.SendMessage(args)) return true;
            switch (args[0].ToLower())
            {
                case "broadcast":
                    return OnBroadcastCommand(args);
                case "relay":
                    return OnRelayCommand(args);
                case "sign":
                    return OnSignCommand(args);
                case "change":
                    return OnChangeCommand(args);
                case "create":
                    return OnCreateCommand(args);
                case "export":
                    return OnExportCommand(args);
                case "help":
                    return OnHelpCommand(args);
                case "plugins":
                    return OnPluginsCommand(args);
                case "import":
                    return OnImportCommand(args);
                case "list":
                    return OnListCommand(args);
                case "claim":
                    return OnClaimCommand(args);
                case "open":
                    return OnOpenCommand(args);
                case "close":
                    return OnCloseCommand(args);
                case "rebuild":
                    return OnRebuildCommand(args);
                case "send":
                    if (ExtensionSettings.Default.WalletConfig.IsBhpFee)
                    {
                        return OnSendCommandEx(args);
                    }
                    else
                    {
                        return OnSendCommand(args);
                    }
                case "show":
                    return OnShowCommand(args);
                case "start":
                    return OnStartCommand(args);
                case "upgrade":
                    return OnUpgradeCommand(args);
                case "deploy":
                    return OnDeployCommand(args);
                case "install":
                    return OnInstallCommand(args);
                case "uninstall":
                    return OnUnInstallCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnBroadcastCommand(string[] args)
        {
            string command = args[1].ToLower();
            ISerializable payload = null;
            switch (command)
            {
                case "addr":
                    payload = AddrPayload.Create(NetworkAddressWithTime.Create(new IPEndPoint(IPAddress.Parse(args[2]), ushort.Parse(args[3])), NetworkAddressWithTime.NODE_NETWORK, DateTime.UtcNow.ToTimestamp()));
                    break;
                case "block":
                    if (args[2].Length == 64 || args[2].Length == 66)
                        payload = Blockchain.Singleton.GetBlock(UInt256.Parse(args[2]));
                    else
                        payload = Blockchain.Singleton.Store.GetBlock(uint.Parse(args[2]));
                    break;
                case "getblocks":
                case "getheaders":
                    payload = GetBlocksPayload.Create(UInt256.Parse(args[2]));
                    break;
                case "getdata":
                case "inv":
                    payload = InvPayload.Create(Enum.Parse<InventoryType>(args[2], true), args.Skip(3).Select(UInt256.Parse).ToArray());
                    break;
                case "tx":
                    payload = Blockchain.Singleton.GetTransaction(UInt256.Parse(args[2]));
                    break;
                default:
                    Console.WriteLine($"Command \"{command}\" is not supported.");
                    return true;
            }
            system.LocalNode.Tell(Message.Create(command, payload));
            return true;
        }

        private bool OnRelayCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("You must input JSON object to relay.");
                return true;
            }
            var jsonObjectToRelay = string.Join(string.Empty, args.Skip(1));
            if (string.IsNullOrWhiteSpace(jsonObjectToRelay))
            {
                Console.WriteLine("You must input JSON object to relay.");
                return true;
            }
            try
            {
                ContractParametersContext context = ContractParametersContext.Parse(jsonObjectToRelay);
                if (!context.Completed)
                {
                    Console.WriteLine("The signature is incomplete.");
                    return true;
                }
                if (!(context.Verifiable is Transaction tx))
                {
                    Console.WriteLine($"Only support to relay transaction.");
                    return true;
                }
                tx.Witnesses = context.GetWitnesses();
                system.LocalNode.Tell(new LocalNode.Relay { Inventory = tx });
                Console.WriteLine($"Data relay success, the hash is shown as follows:\r\n{tx.Hash}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"One or more errors occurred:\r\n{e.Message}");
            }
            return true;
        }

        private bool OnSignCommand(string[] args)
        {
            if (NoWallet()) return true;

            if (args.Length < 2)
            {
                Console.WriteLine("You must input JSON object pending signature data.");
                return true;
            }
            var jsonObjectToSign = string.Join(string.Empty, args.Skip(1));
            if (string.IsNullOrWhiteSpace(jsonObjectToSign))
            {
                Console.WriteLine("You must input JSON object pending signature data.");
                return true;
            }
            try
            {
                ContractParametersContext context = ContractParametersContext.Parse(jsonObjectToSign);
                if (!Program.Wallet.Sign(context))
                {
                    Console.WriteLine("The private key that can sign the data is not found.");
                    return true;
                }
                Console.WriteLine($"Signed Output:\r\n{context}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"One or more errors occurred:\r\n{e.Message}");
            }
            return true;
        }

        private bool OnChangeCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "view":
                    return OnChangeViewCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnChangeViewCommand(string[] args)
        {
            if (args.Length != 3) return false;
            if (!byte.TryParse(args[2], out byte viewnumber)) return false;
            system.Consensus?.Tell(new ConsensusService.SetViewNumber { ViewNumber = viewnumber });
            return true;
        }

        private bool OnCreateCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "address":
                    return OnCreateAddressCommand(args);
                case "wallet":
                    return OnCreateWalletCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnCreateAddressCommand(string[] args)
        {
            if (NoWallet()) return true;
            if (args.Length > 3)
            {
                Console.WriteLine("error");
                return true;
            }

            ushort count;
            if (args.Length >= 3)
                count = ushort.Parse(args[2]);
            else
                count = 1;

            int x = 0;
            List<string> addresses = new List<string>();

            Parallel.For(0, count, (i) =>
            {
                WalletAccount account = Program.Wallet.CreateAccount();

                lock (addresses)
                {
                    x++;
                    addresses.Add(account.Address);
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"[{x}/{count}]");
                }
            });

            if (Program.Wallet is BRC6Wallet wallet)
                wallet.Save();
            Console.WriteLine();
            string path = $"address{DateTime.Now.ToString("yyyyMMddHHmmssfff")}.txt";
            Console.WriteLine($"export addresses to {path}");
            File.WriteAllLines(path, addresses);
            return true;
        }

        private bool OnCreateWalletCommand(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("error");
                return true;
            }
            string path = args[2];
            string password = ReadUserInput("password", true);
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            if (!RpcExtension.VerifyPW(password))
            {
                Console.WriteLine($"password max length {RpcExtension.MaxPWLength}");
                return true;
            }
            string password2 = ReadUserInput("password", true);
            if (password != password2)
            {
                Console.WriteLine("error");
                return true;
            }
            switch (Path.GetExtension(path))
            {
                case ".db3":
                    {
                        Program.Wallet = UserWallet.Create(GetIndexer(), path, password);
                        WalletAccount account = Program.Wallet.CreateAccount();
                        Console.WriteLine($"address: {account.Address}");
                        Console.WriteLine($" pubkey: {account.GetKey().PublicKey.EncodePoint(true).ToHexString()}");
                        system.RpcServer?.OpenWallet(Program.Wallet);
                    }
                    break;
                case ".json":
                    {
                        BRC6Wallet wallet = new BRC6Wallet(GetIndexer(), path);
                        wallet.Unlock(password);
                        WalletAccount account = wallet.CreateAccount();
                        wallet.Save();
                        Program.Wallet = wallet;
                        Console.WriteLine($"address: {account.Address}");
                        Console.WriteLine($" pubkey: {account.GetKey().PublicKey.EncodePoint(true).ToHexString()}");
                        system.RpcServer?.OpenWallet(Program.Wallet);
                    }
                    break;
                default:
                    Console.WriteLine("Wallet files in that format are not supported, please use a .json or .db3 file extension.");
                    break;
            }
            return true;
        }

        private bool OnExportCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "key":
                    return OnExportKeyCommand(args);
                case "wallet":
                    return OnExportWalletCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnExportKeyCommand(string[] args)
        {
            if (NoWallet()) return true;
            if (args.Length < 2 || args.Length > 4)
            {
                Console.WriteLine("error");
                return true;
            }
            UInt160 scriptHash = null;
            string path = null;
            if (args.Length == 3)
            {
                try
                {
                    scriptHash = args[2].ToScriptHash();
                }
                catch (FormatException)
                {
                    path = args[2];
                }
            }
            else if (args.Length == 4)
            {
                scriptHash = args[2].ToScriptHash();
                path = args[3];
            }

            if (path != null && File.Exists(path))
            {
                Console.WriteLine("file is exist");
                return true;
            }

            string password = ReadUserInput("password", true);
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            if (!RpcExtension.VerifyPW(password))
            {
                Console.WriteLine($"password max length {RpcExtension.MaxPWLength}");
                return true;
            }
            if (!Program.Wallet.VerifyPassword(password))
            {
                Console.WriteLine("Incorrect password");
                return true;
            }
            IEnumerable<KeyPair> keys;
            if (scriptHash == null)
                keys = Program.Wallet.GetAccounts().Where(p => p.HasKey).Select(p => p.GetKey());
            else
                keys = new[] { Program.Wallet.GetAccount(scriptHash).GetKey() };
            if (path == null)
                foreach (KeyPair key in keys)
                    Console.WriteLine(key.Export());
            else
                File.WriteAllLines(path, keys.Select(p => p.Export()));
            return true;
        }

        private bool OnExportWalletCommand(string[] args)
        {
            if (NoWallet()) return true;
            if (args.Length != 3)
            {
                Console.WriteLine("error");
                return true;
            }

            string path = args[2];
            if (File.Exists(path))
            {
                Console.WriteLine("file is exist");
                return true;
            }

            string password = ReadUserInput("password", true);
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            if (!RpcExtension.VerifyPW(password))
            {
                Console.WriteLine($"password max length {RpcExtension.MaxPWLength}");
                return true;
            }
            if (!Program.Wallet.VerifyPassword(password))
            {
                Console.WriteLine("Incorrect password");
                return true;
            }

            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write))
                {
                    using (StreamWriter sw = new StreamWriter(fs))
                    {
                        int x = 0;
                        int count = Program.Wallet.GetAccounts().Where(p => p.HasKey).Count();
                        foreach (WalletAccount account in Program.Wallet.GetAccounts().Where(p => p.HasKey))
                        {
                            x++;
                            //WIF 私钥 公钥 地址   
                            KeyPair key = account.GetKey();
                            sw.WriteLine($"{key.Export()} {key.PrivateKey.ToHexString()} {key.PublicKey.EncodePoint(true).ToHexString()} {account.Address}");
                            sw.Flush();
                            Console.SetCursorPosition(0, Console.CursorTop);
                            Console.Write($"[{x}/{count}]");
                        }
                        sw.Flush();
                        sw.Close();
                    }
                    fs.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine($"Export wallet failed");
                return true;
            }
            Console.WriteLine();
            Console.WriteLine($"Export wallet to {path} success");
            return true;
        }

        private bool OnHelpCommand(string[] args)
        {
            Console.Write(
                "Normal Commands:\n" +
                "\tversion\n" +
                "\thelp [plugin-name]\n" +
                "\tclear\n" +
                "\texit\n" +
                "Wallet Commands:\n" +
                "\tcreate wallet <path>\n" +
                "\topen wallet <path>\n" +
                "\tclose wallet\n" +
                "\tupgrade wallet <path>\n" +
                "\trebuild index\n" +
                "\tlist address\n" +
                "\tlist asset\n" +
                "\tlist key\n" +
                "\tshow utxo [id|alias]\n" +
                "\tshow gas\n" +
                "\tclaim gas [all] [changeAddress]\n" +
                "\tcreate address [n=1]\n" +
                "\timport key <wif|path>\n" +
                "\texport key [address] [path]\n" +
                "\texport wallet <path>\n" +
                "\timport multisigaddress m pubkeys...\n" +
                "\tsend <id|alias> <address> <value>|all [fee=0]\n" +
                "\tsign <jsonObjectToSign>\n" +
                 "Contract Commands:\n" +
                "\tdeploy <avmFilePath> <paramTypes> <returnTypeHexString> <hasStorage (true|false)> <hasDynamicInvoke (true|false)> <isPayable (true|false) <contractName> <contractVersion> <contractAuthor> <contractEmail> <contractDescription>\n" +
                "Node Commands:\n" +
                "\tshow state\n" +
                "\tshow pool [verbose]\n" +
                "\trelay <jsonObjectToSign>\n" +
                "Plugin Commands:\n" +
                "\tplugins\n" +
                "\tinstall <pluginName>\n" +
                "\tuninstall <pluginName>\n" +
                "Advanced Commands:\n" +
                "\tstart consensus\n");
            return true;
        }

        private bool OnPluginsCommand(string[] args)
        {
            if (Plugin.Plugins.Count > 0)
            {
                Console.WriteLine("Loaded plugins:");
                Plugin.Plugins.ForEach(p => Console.WriteLine("\t" + p.Name));
            }
            else
            {
                Console.WriteLine("No loaded plugins");
            }
            return true;
        }

        private bool OnImportCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "key":
                    return OnImportKeyCommand(args);
                case "multisigaddress":
                    return OnImportMultisigAddress(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnImportMultisigAddress(string[] args)
        {
            if (NoWallet()) return true;

            if (args.Length < 4)
            {
                Console.WriteLine("Error. Invalid parameters.");
                return true;
            }

            int m = int.Parse(args[2]);
            int n = args.Length - 3;

            if (m < 1 || m > n || n > 1024)
            {
                Console.WriteLine("Error. Invalid parameters.");
                return true;
            }

            ECPoint[] publicKeys = args.Skip(3).Select(p => ECPoint.Parse(p, ECCurve.Secp256)).ToArray();

            Contract multiSignContract = Contract.CreateMultiSigContract(m, publicKeys);
            KeyPair keyPair = Program.Wallet.GetAccounts().FirstOrDefault(p => p.HasKey && publicKeys.Contains(p.GetKey().PublicKey))?.GetKey();

            WalletAccount account = Program.Wallet.CreateAccount(multiSignContract, keyPair);
            if (Program.Wallet is BRC6Wallet wallet)
                wallet.Save();

            Console.WriteLine("Multisig. Addr.: " + multiSignContract.Address);

            return true;
        }

        private bool OnImportKeyCommand(string[] args)
        {
            if (args.Length > 3)
            {
                Console.WriteLine("error");
                return true;
            }
            byte[] prikey = null;
            try
            {
                prikey = Wallet.GetPrivateKeyFromWIF(args[2]);
            }
            catch (FormatException) { }
            if (prikey == null)
            {
                var file = new FileInfo(args[2]);

                if (!file.Exists)
                {
                    Console.WriteLine($"Error: File '{file.FullName}' doesn't exists");
                    return true;
                }

                if (file.Length > 1024 * 1024)
                {
                    if (ReadUserInput($"The file '{file.FullName}' is too big, do you want to continue? (yes|no)", false)?.ToLowerInvariant() != "yes") return true;
                }

                string[] lines = File.ReadAllLines(args[2]);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].Length == 64)
                        prikey = lines[i].HexToBytes();
                    else
                        prikey = Wallet.GetPrivateKeyFromWIF(lines[i]);
                    Program.Wallet.CreateAccount(prikey);
                    Array.Clear(prikey, 0, prikey.Length);
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"[{i + 1}/{lines.Length}]");
                }
                Console.WriteLine();
            }
            else
            {
                WalletAccount account = Program.Wallet.CreateAccount(prikey);
                Array.Clear(prikey, 0, prikey.Length);
                Console.WriteLine($"address: {account.Address}");
                Console.WriteLine($" pubkey: {account.GetKey().PublicKey.EncodePoint(true).ToHexString()}");
            }
            if (Program.Wallet is BRC6Wallet wallet)
                wallet.Save();
            return true;
        }

        private bool OnListCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "address":
                    return OnListAddressCommand(args);
                case "asset":
                    return OnListAssetCommand(args);
                case "key":
                    return OnListKeyCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnClaimCommand(string[] args)
        {
            if (args.Length < 2 || args.Length > 4 || !args[1].Equals("gas", StringComparison.OrdinalIgnoreCase))
                return base.OnCommand(args);

            if (NoWallet()) return true;

            bool all = args.Length > 2 && args[2].Equals("all", StringComparison.OrdinalIgnoreCase);
            bool useChangeAddress = (all && args.Length == 4) || (!all && args.Length == 3);
            UInt160 changeAddress = useChangeAddress ? args[args.Length - 1].ToScriptHash() : null;

            if (useChangeAddress)
            {
                string password = ReadUserInput("password", true);
                if (password.Length == 0)
                {
                    Console.WriteLine("cancelled");
                    return true;
                }
                if (!RpcExtension.VerifyPW(password))
                {
                    Console.WriteLine($"password max length {RpcExtension.MaxPWLength}");
                    return true;
                }
                if (!Program.Wallet.VerifyPassword(password))
                {
                    Console.WriteLine("Incorrect password");
                    return true;
                }
            }

            Coins coins = new Coins(Program.Wallet, system);
            ClaimTransaction[] txs = all
                ? coins.ClaimAll(changeAddress)
                : new[] { coins.Claim(changeAddress) };
            if (txs is null) return true;
            foreach (ClaimTransaction tx in txs)
                if (tx != null)
                    Console.WriteLine($"Transaction Succeeded: {tx.Hash}");
            return true;
        }

        private bool OnShowGasCommand(string[] args)
        {
            if (NoWallet()) return true;

            Coins coins = new Coins(Program.Wallet, system);
            Console.WriteLine($"unavailable: {coins.UnavailableBonus().ToString()}");
            Console.WriteLine($"  available: {coins.AvailableBonus().ToString()}");
            return true;
        }

        private bool OnListKeyCommand(string[] args)
        {
            if (NoWallet()) return true;
            foreach (KeyPair key in Program.Wallet.GetAccounts().Where(p => p.HasKey).Select(p => p.GetKey()))
            {
                Console.WriteLine(key.PublicKey);
            }
            return true;
        }

        private bool OnListAddressCommand(string[] args)
        {
            if (NoWallet()) return true;
            foreach (Contract contract in Program.Wallet.GetAccounts().Where(p => !p.WatchOnly).Select(p => p.Contract))
            {
                Console.WriteLine($"{contract.Address}\t{(contract.Script.IsStandardContract() ? "Standard" : "Nonstandard")}");
            }
            return true;
        }

        private bool OnListAssetCommand(string[] args)
        {
            if (NoWallet()) return true;
            foreach (var item in Program.Wallet.GetCoins().Where(p => !p.State.HasFlag(CoinState.Spent)).GroupBy(p => p.Output.AssetId, (k, g) => new
            {
                Asset = Blockchain.Singleton.Store.GetAssets().TryGet(k),
                Balance = g.Sum(p => p.Output.Value),
                Confirmed = g.Where(p => p.State.HasFlag(CoinState.Confirmed)).Sum(p => p.Output.Value)
            }))
            {
                Console.WriteLine($"       id:{item.Asset.AssetId}");
                Console.WriteLine($"     name:{item.Asset.GetName()}");
                Console.WriteLine($"  balance:{item.Balance}");
                Console.WriteLine($"confirmed:{item.Confirmed}");
                Console.WriteLine();
            }
            return true;
        }

        private bool OnOpenCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "wallet":
                    return OnOpenWalletCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnCloseCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "wallet":
                    return onCloseWalletCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        //TODO: 目前没有想到其它安全的方法来保存密码
        //所以只能暂时手动输入，但如此一来就不能以服务的方式启动了
        //未来再想想其它办法，比如采用智能卡之类的
        private bool OnOpenWalletCommand(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("error");
                return true;
            }
            string path = args[2];
            if (!File.Exists(path))
            {
                Console.WriteLine($"File does not exist");
                return true;
            }
            string password = ReadUserInput("password", true);
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            if (!RpcExtension.VerifyPW(password))
            {
                Console.WriteLine($"password max length {RpcExtension.MaxPWLength}");
                return true;
            }
            try
            {
                Program.Wallet = OpenWallet(GetIndexer(), path, password);
            }
            catch (CryptographicException)
            {
                Console.WriteLine($"failed to open file \"{path}\"");
            }
            system.RpcServer?.OpenWallet(Program.Wallet);
            return true;
        }

        private bool onCloseWalletCommand(string[] args)
        {
            if (Program.Wallet == null)
            {
                Console.WriteLine($"Wallet is not opened");
                return true;
            }

            Program.Wallet.Dispose();
            Program.Wallet = null;

            if (system.RpcServer != null)
            {
                system.RpcServer.CloseWallet();
            }

            Console.WriteLine($"Wallet is closed");
            return true;
        }

        private bool OnRebuildCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "index":
                    return OnRebuildIndexCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnRebuildIndexCommand(string[] args)
        {
            GetIndexer().RebuildIndex();
            return true;
        }

        private bool OnSendCommand(string[] args)
        {
            if (args.Length < 4 || args.Length > 5)
            {
                Console.WriteLine("error");
                return true;
            }
            if (NoWallet()) return true;
            string password = ReadUserInput("password", true);
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            if (!RpcExtension.VerifyPW(password))
            {
                Console.WriteLine($"password max length {RpcExtension.MaxPWLength}");
                return true;
            }
            if (!Program.Wallet.VerifyPassword(password))
            {
                Console.WriteLine("Incorrect password");
                return true;
            }
            UIntBase assetId;
            switch (args[1].ToLower())
            {
                case "bhp":
                    assetId = Blockchain.GoverningToken.Hash;
                    break;
                case "gas":
                    assetId = Blockchain.UtilityToken.Hash;
                    break;
                default:
                    assetId = UIntBase.Parse(args[1]);
                    break;
            }
            UInt160 scriptHash = args[2].ToScriptHash();
            bool isSendAll = string.Equals(args[3], "all", StringComparison.OrdinalIgnoreCase);
            Transaction tx;
            if (isSendAll)
            {
                Coin[] coins = Program.Wallet.FindUnspentCoins().Where(p => p.Output.AssetId.Equals(assetId)).ToArray();
                tx = new ContractTransaction
                {
                    Attributes = new TransactionAttribute[0],
                    Inputs = coins.Select(p => p.Reference).ToArray(),
                    Outputs = new[]
                    {
                        new TransactionOutput
                        {
                            AssetId = (UInt256)assetId,
                            Value = coins.Sum(p => p.Output.Value),
                            ScriptHash = scriptHash
                        }
                    }
                };
                if (assetId.Equals(Blockchain.GoverningToken.Hash))
                {
                    tx.Outputs[0].Value -= BhpExtensions.Fees.BhpTxFee.EstimateTxFee(tx);
                    if (tx.Outputs[0].Value <= Fixed8.Zero)
                    {
                        Console.WriteLine("Insufficient funds.");
                        return true;
                    }
                }
            }
            else
            {
                AssetDescriptor descriptor = new AssetDescriptor(assetId);
                if (!BigDecimal.TryParse(args[3], descriptor.Decimals, out BigDecimal amount))
                {
                    Console.WriteLine("Incorrect Amount Format");
                    return true;
                }
                Fixed8 fee = args.Length >= 5 ? Fixed8.Parse(args[4]) : Fixed8.Zero;
                tx = Program.Wallet.MakeTransaction(null, new[]
                {
                    new TransferOutput
                    {
                        AssetId = assetId,
                        Value = amount,
                        ScriptHash = scriptHash
                    }
                }, fee: fee);
                if (tx == null)
                {
                    Console.WriteLine("Insufficient funds");
                    return true;
                }
            }
            ContractParametersContext context = new ContractParametersContext(tx);
            Program.Wallet.Sign(context);
            if (context.Completed)
            {
                tx.Witnesses = context.GetWitnesses();

                if (tx.Size > Transaction.MaxTransactionSize)
                {
                    Console.WriteLine("The size of the free transaction must be less than 102400 bytes");
                    return true;
                }

                Program.Wallet.ApplyTransaction(tx);
                system.LocalNode.Tell(new LocalNode.Relay { Inventory = tx });
                Console.WriteLine($"TXID: {tx.Hash}");
            }
            else
            {
                Console.WriteLine("SignatureContext:");
                Console.WriteLine(context.ToString());
            }
            return true;
        }

        //BHP
        private bool OnSendCommandEx(string[] args)
        {
            if (args.Length < 4 || args.Length > 5)
            {
                Console.WriteLine("error");
                return true;
            }
            if (NoWallet()) return true;
            string password = ReadUserInput("password", true);
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            if (!RpcExtension.VerifyPW(password))
            {
                Console.WriteLine($"password max length {RpcExtension.MaxPWLength}");
                return true;
            }
            if (!Program.Wallet.VerifyPassword(password))
            {
                Console.WriteLine("Incorrect password");
                return true;
            }
            UIntBase assetId;
            switch (args[1].ToLower())
            {
                case "bhp":
                    assetId = Blockchain.GoverningToken.Hash;
                    break;
                case "gas":
                    assetId = Blockchain.UtilityToken.Hash;
                    break;
                default:
                    assetId = UIntBase.Parse(args[1]);
                    break;
            }
            UInt160 scriptHash = args[2].ToScriptHash();
            bool isSendAll = string.Equals(args[3], "all", StringComparison.OrdinalIgnoreCase);
            Transaction tx;
            if (isSendAll)
            {
                Coin[] coins = Program.Wallet.FindUnspentCoins().Where(p => p.Output.AssetId.Equals(assetId)).ToArray();
                tx = new ContractTransaction
                {
                    Attributes = new TransactionAttribute[0],
                    Inputs = coins.Select(p => p.Reference).ToArray(),
                    Outputs = new[]
                    {
                        new TransactionOutput
                        {
                            AssetId = (UInt256)assetId,
                            Value = coins.Sum(p => p.Output.Value),
                            ScriptHash = scriptHash
                        }
                    }
                };
                if (assetId.Equals(Blockchain.GoverningToken.Hash))
                {
                    tx.Outputs[0].Value -= BhpExtensions.Fees.BhpTxFee.EstimateTxFee(tx);
                    if (tx.Outputs[0].Value <= Fixed8.Zero)
                    {
                        Console.WriteLine("Insufficient funds.");
                        return true;
                    }
                }
                else if (!assetId.Equals(Blockchain.UtilityToken.Hash))
                {
                    tx = Bhp.BhpExtensions.Transactions.TransactionContract.EstimateFee(Program.Wallet, tx, null, null);
                    if (tx == null)
                    {
                        Console.WriteLine("Insufficient funds");
                        return true;
                    }
                }
            }
            else
            {
                AssetDescriptor descriptor = new AssetDescriptor(assetId);
                if (!BigDecimal.TryParse(args[3], descriptor.Decimals, out BigDecimal amount))
                {
                    Console.WriteLine("Incorrect Amount Format");
                    return true;
                }
                Fixed8 fee = args.Length >= 5 ? Fixed8.Parse(args[4]) : Fixed8.Zero;
                tx = Program.Wallet.MakeTransaction(null, new[]
                {
                    new TransferOutput
                    {
                        AssetId = assetId,
                        Value = amount,
                        ScriptHash = scriptHash
                    }
                }, fee: fee);
                if (tx == null)
                {
                    Console.WriteLine("Insufficient funds");
                    return true;
                }
            }
            ContractParametersContext context = new ContractParametersContext(tx);
            Program.Wallet.Sign(context);
            if (context.Completed)
            {
                tx.Witnesses = context.GetWitnesses();

                if (tx.Size > Transaction.MaxTransactionSize)
                {
                    Console.WriteLine("The size of the free transaction must be less than 102400 bytes");
                    return true;
                }

                Program.Wallet.ApplyTransaction(tx);
                system.LocalNode.Tell(new LocalNode.Relay { Inventory = tx });
                Console.WriteLine($"TXID: {tx.Hash}");
            }
            else
            {
                Console.WriteLine("SignatureContext:");
                Console.WriteLine(context.ToString());
            }
            return true;
        }

        private bool OnShowCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "gas":
                    return OnShowGasCommand(args);
                case "pool":
                    return OnShowPoolCommand(args);
                case "state":
                    return OnShowStateCommand(args);
                case "utxo":
                    return OnShowUtxoCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnShowPoolCommand(string[] args)
        {
            bool verbose = args.Length >= 3 && args[2] == "verbose";
            if (verbose)
            {
                Blockchain.Singleton.MemPool.GetVerifiedAndUnverifiedTransactions(
                    out IEnumerable<Transaction> verifiedTransactions,
                    out IEnumerable<Transaction> unverifiedTransactions);
                Console.WriteLine("Verified Transactions:");
                foreach (Transaction tx in verifiedTransactions)
                    Console.WriteLine($" {tx.Hash} {tx.GetType().Name} {tx.NetworkFee} GAS_NetFee {tx.IsLowPriority}");
                Console.WriteLine("Unverified Transactions:");
                foreach (Transaction tx in unverifiedTransactions)
                    Console.WriteLine($" {tx.Hash} {tx.GetType().Name} {tx.NetworkFee} GAS_NetFee {tx.IsLowPriority}");
            }
            Console.WriteLine($"total: {Blockchain.Singleton.MemPool.Count}, verified: {Blockchain.Singleton.MemPool.VerifiedCount}, unverified: {Blockchain.Singleton.MemPool.UnVerifiedCount}");
            return true;
        }

        /*
        private bool OnShowStateCommand(string[] args)
        {
            bool stop = false;
            Console.CursorVisible = false;
            Console.Clear();
            Task task = Task.Run(async () =>
            {
                while (!stop)
                {
                    Console.SetCursorPosition(0, 0);
                    uint wh = 0;
                    if (Program.Wallet != null)
                        wh = (Program.Wallet.WalletHeight > 0) ? Program.Wallet.WalletHeight - 1 : 0;

                    WriteLineWithoutFlicker($"block: {wh}/{Blockchain.Singleton.Height}/{Blockchain.Singleton.HeaderHeight}  connected: {LocalNode.Singleton.ConnectedCount}  unconnected: {LocalNode.Singleton.UnconnectedCount}");
                    int linesWritten = 1;
                    foreach (RemoteNode node in LocalNode.Singleton.GetRemoteNodes().Take(Console.WindowHeight - 2).ToArray())
                    {
                        WriteLineWithoutFlicker(
                            $"  ip: {node.Remote.Address.ToString().PadRight(15)}\tport: {node.Remote.Port.ToString().PadRight(5)}\tlisten: {node.ListenerPort.ToString().PadRight(5)}\theight: {node.LastBlockIndex}");
                        linesWritten++;
                    }

                    while (++linesWritten < Console.WindowHeight)
                        WriteLineWithoutFlicker();
                    await Task.Delay(500);
                }
            });
            Console.ReadLine();
            stop = true;
            task.Wait();
            Console.WriteLine();
            Console.CursorVisible = true;
            return true;
        }
        */

        private static void WriteLineWithoutFlicker(string msg = "", int maxWidth = 80)
        {
            if (msg.Length > 0) Console.Write(msg);
            var spacesToErase = maxWidth - msg.Length;
            if (spacesToErase < 0) spacesToErase = 0;
            Console.WriteLine(new string(' ', spacesToErase));
        }

        private bool OnShowStateCommand(string[] args)
        {
            bool stop = false;
            Console.CursorVisible = false;
            Console.Clear();
            Task task = Task.Run(async () =>
            {
                while (!stop)
                {
                    Console.SetCursorPosition(0, 0);
                    uint wh = 0;
                    if (Program.Wallet != null)
                        wh = (Program.Wallet.WalletHeight > 0) ? Program.Wallet.WalletHeight - 1 : 0;

                    WriteLineWithoutFlicker("------------------------------RemoteNode List------------------------------");
                    WriteLineWithoutFlicker($"block: {wh}/{Blockchain.Singleton.Height}/{Blockchain.Singleton.HeaderHeight}  connected: {LocalNode.Singleton.ConnectedCount}  unconnected: {LocalNode.Singleton.UnconnectedCount}");
                    int linesWritten = 2;
                    foreach (RemoteNode node in LocalNode.Singleton.GetRemoteNodes().Take(Console.WindowHeight - 2).ToArray())
                    {
                        WriteLineWithoutFlicker(
                            $"  ip: {node.Remote.Address.ToString().PadRight(15)}\tport: {node.Remote.Port.ToString().PadRight(5)}\tlisten: {node.ListenerPort.ToString().PadRight(5)}\theight: {node.LastBlockIndex}");
                        linesWritten++;
                    }

                    while (++linesWritten < Console.WindowHeight)
                        WriteLineWithoutFlicker();
                    await Task.Delay(500);
                }
            });
            Console.ReadLine();
            stop = true;
            task.Wait();
            Console.WriteLine();
            Console.CursorVisible = true;
            return true;
        }

        private bool OnShowUtxoCommand(string[] args)
        {
            if (NoWallet()) return true;
            IEnumerable<Coin> coins = Program.Wallet.FindUnspentCoins();
            if (args.Length >= 3)
            {
                UInt256 assetId;
                switch (args[2].ToLower())
                {
                    case "bhp":
                        assetId = Blockchain.GoverningToken.Hash;
                        break;
                    case "gas":
                        assetId = Blockchain.UtilityToken.Hash;
                        break;
                    default:
                        assetId = UInt256.Parse(args[2]);
                        break;
                }
                coins = coins.Where(p => p.Output.AssetId.Equals(assetId));
            }
            Coin[] coins_array = coins.ToArray();
            const int MAX_SHOW = 100;
            for (int i = 0; i < coins_array.Length && i < MAX_SHOW; i++)
                Console.WriteLine($"{coins_array[i].Reference.PrevHash}:{coins_array[i].Reference.PrevIndex}");
            if (coins_array.Length > MAX_SHOW)
                Console.WriteLine($"({coins_array.Length - MAX_SHOW} more)");
            Console.WriteLine($"total: {coins_array.Length} UTXOs");
            return true;
        }

        protected internal override void OnStart(string[] args)
        {
            bool useRPC = false;
            for (int i = 0; i < args.Length; i++)
                switch (args[i])
                {
                    case "/rpc":
                    case "--rpc":
                    case "-r":
                        useRPC = true;
                        break;
                }
            store = new LevelDBStore(Path.GetFullPath(Settings.Default.Paths.Chain));
            system = new BhpSystem(store);
            system.StartNode(
                Settings.Default.P2P.Port,
                Settings.Default.P2P.WsPort,
                Settings.Default.P2P.MinDesiredConnections,
                Settings.Default.P2P.MaxConnections,
                Settings.Default.P2P.MaxConnectionsPerAddress);
            if (Settings.Default.UnlockWallet.IsActive)
            {
                try
                {
                    Program.Wallet = OpenWallet(GetIndexer(), Settings.Default.UnlockWallet.Path, Settings.Default.UnlockWallet.Password);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine($"failed to open file \"{Settings.Default.UnlockWallet.Path}\"");
                }
                if (Settings.Default.UnlockWallet.StartConsensus && Program.Wallet != null)
                {
                    OnStartConsensusCommand(null);
                }
            }

            //By BHP
            ExtensionSettings.Default.DataRPCServer.Host = Settings.Default.DataRPC.Host;
            ExtensionSettings.Default.WalletConfig.Index = Settings.Default.Paths.Index;
            ExtensionSettings.Default.WalletConfig.Path = Settings.Default.UnlockWallet.Path;
            ExtensionSettings.Default.WalletConfig.AutoLock = Settings.Default.UnlockWallet.AutoLock;
            ExtensionSettings.Default.WalletConfig.Indexer = GetIndexer();
            ExtensionSettings.Default.WalletConfig.IsBhpFee = Settings.Default.UnlockWallet.IsBhpFee;

            if (useRPC)
            {
                system.StartRpc(Settings.Default.RPC.BindAddress,
                    Settings.Default.RPC.Port,
                    wallet: Program.Wallet,
                    sslCert: Settings.Default.RPC.SslCert,
                    password: Settings.Default.RPC.SslCertPassword,
                    maxGasInvoke: Settings.Default.RPC.MaxGasInvoke);
            }

            if (Settings.Default.ExportWallet.IsActive)
            {
                exportWalletTimer = new System.Timers.Timer();
                exportWalletTimer.Interval = Settings.Default.ExportWallet.Interval * 60 * 60 * 1000;
                exportWalletTimer.Elapsed += ExportWalletTimer_Elapsed;
                exportWalletTimer.Start();
            }
        }

        private void ExportWalletTimer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            if (Program.Wallet == null || Program.Wallet.GetAccounts().Count() <= 0) return;
            string walletName = Path.GetFileNameWithoutExtension(Program.Wallet.WalletPath);
            try
            {
                string path = Path.Combine(Settings.Default.ExportWallet.Path, $"{walletName}{DateTime.Now.ToString("yyyyMMddHHmmss")}.txt");
                using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write))
                {
                    using (StreamWriter sw = new StreamWriter(fs))
                    {
                        foreach (WalletAccount account in Program.Wallet.GetAccounts().Where(p => p.HasKey))
                        {
                            //WIF 私钥 公钥 地址  
                            KeyPair key = account.GetKey();
                            sw.WriteLine($"{key.Export()} {key.PrivateKey.ToHexString()} {key.PublicKey.EncodePoint(true).ToHexString()} {account.Address}");
                            sw.Flush();
                        }
                        sw.Flush();
                        sw.Close();
                    }
                    fs.Close();
                }
            }
            catch (Exception ex)
            {
            }
        }

        private bool OnStartCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "consensus":
                    return OnStartConsensusCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnStartConsensusCommand(string[] args)
        {
            if (NoWallet()) return true;
            ShowPrompt = false;
            system.StartConsensus(Program.Wallet);
            return true;
        }

        protected internal override void OnStop()
        {
            if (exportWalletTimer != null)
            {
                exportWalletTimer.Stop();
                exportWalletTimer.Dispose();
            }
            system.Dispose();
            store.Dispose();
        }

        private bool OnUpgradeCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "wallet":
                    return OnUpgradeWalletCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnDeployCommand(string[] args)
        {
            if (NoWallet()) return true;
            var tx = LoadScriptTransaction(
                /* filePath */ args[1],
                /* paramTypes */ args[2],
                /* returnType */ args[3],
                /* hasStorage */ args[4].ToBool(),
                /* hasDynamicInvoke */ args[5].ToBool(),
                /* isPayable */ args[6].ToBool(),
                /* contractName */ args[7],
                /* contractVersion */ args[8],
                /* contractAuthor */ args[9],
                /* contractEmail */ args[10],
                /* contractDescription */ args[11],
                /* scriptHash */ out var scriptHash);

            tx.Version = 1;
            if (tx.Attributes == null) tx.Attributes = new TransactionAttribute[0];
            if (tx.Inputs == null) tx.Inputs = new CoinReference[0];
            if (tx.Outputs == null) tx.Outputs = new TransactionOutput[0];
            if (tx.Witnesses == null) tx.Witnesses = new Witness[0];
            using (ApplicationEngine engine = ApplicationEngine.Run(tx.Script, tx, testMode: true))
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine($"Script hash: {scriptHash.ToString()}");
                sb.AppendLine($"VM State: {engine.State}");
                sb.AppendLine($"Gas Consumed: {engine.GasConsumed}");
                sb.AppendLine($"Evaluation Stack: {new JArray(engine.ResultStack.Select(p => p.ToParameter().ToJson()))}");
                JObject notifications = engine.Service.Notifications.Select(q =>
                {
                    JObject notification = new JObject();
                    notification["contract"] = q.ScriptHash.ToString();
                    try
                    {
                        notification["state"] = q.State.ToParameter().ToJson();
                    }
                    catch (InvalidOperationException)
                    {
                        notification["state"] = "error: recursive reference";
                    }
                    return notification;
                }).ToArray();
                sb.AppendLine($"Notifications: {notifications}");
                Console.WriteLine(sb.ToString());
                if (engine.State.HasFlag(VMState.FAULT))
                {
                    Console.WriteLine("Engine faulted.");
                    return true;
                }

                tx.Gas = InvocationTransaction.GetGas(engine.GasConsumed);
            }

            tx = Program.Wallet.MakeTransaction(new InvocationTransaction
            {
                Version = tx.Version,
                Script = tx.Script,
                Gas = tx.Gas,
                Attributes = tx.Attributes,
                Inputs = tx.Inputs,
                Outputs = tx.Outputs
            });

            return SignAndSendTx(tx);
        }

        public InvocationTransaction LoadScriptTransaction(
           string avmFilePath, string paramTypes, string returnTypeHexString,
           bool hasStorage, bool hasDynamicInvoke, bool isPayable,
           string name, string version, string author,
           string email, string description, out UInt160 scriptHash)
        {
            var info = new FileInfo(avmFilePath);
            if (!info.Exists || info.Length >= Transaction.MaxTransactionSize)
            {
                throw new ArgumentException(nameof(avmFilePath));
            }

            byte[] script = File.ReadAllBytes(avmFilePath);
            byte[] parameter_list = paramTypes.HexToBytes();
            ContractParameterType return_type = returnTypeHexString.HexToBytes()
                .Select(p => (ContractParameterType?)p).FirstOrDefault() ?? ContractParameterType.Void;
            ContractPropertyState properties = ContractPropertyState.NoProperty;
            if (hasStorage) properties |= ContractPropertyState.HasStorage;
            if (hasDynamicInvoke) properties |= ContractPropertyState.HasDynamicInvoke;
            if (isPayable) properties |= ContractPropertyState.Payable;

            using (ScriptBuilder sb = new ScriptBuilder())
            {
                scriptHash = script.ToScriptHash();

                sb.EmitSysCall("Bhp.Contract.Create", script, parameter_list, return_type, properties, name, version, author, email, description);
                return new InvocationTransaction
                {
                    Script = sb.ToArray()
                };
            }
        }

        public bool SignAndSendTx(InvocationTransaction tx)
        {
            if (tx == null)
            {
                Console.WriteLine("Insufficient funds, transaction cannot be initiated.");
                return true;
            }
            ContractParametersContext context;
            try
            {
                context = new ContractParametersContext(tx);
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("Blockchain unsynchronized, transaction cannot be sent.");
                throw;
            }
            Program.Wallet.Sign(context);
            if (context.Completed)
            {
                tx.Witnesses = context.GetWitnesses();
                if (tx.Size > Transaction.MaxTransactionSize)
                {
                    Console.WriteLine("The size of the free transaction must be less than 102400 bytes");
                    return true;
                }

                Program.Wallet.ApplyTransaction(tx);
                system.LocalNode.Tell(new LocalNode.Relay { Inventory = tx });
                Console.WriteLine($"Signed and relayed transaction with hash={tx.Hash}");
                return true;
            }

            Console.WriteLine($"Failed sending transaction with hash={tx.Hash}");
            return true;
        }

        //by bhp
        /*
        private bool OnInstallCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("error");
                return true;
            }

            bool isTemp;
            string fileName;
            var pluginName = args[1];

            if (!File.Exists(pluginName))
            {
                if (string.IsNullOrEmpty(Settings.Default.PluginURL))
                {
                    Console.WriteLine("You must define `PluginURL` in your `config.json`");
                    return true;
                }

                var address = string.Format(Settings.Default.PluginURL, pluginName, typeof(Plugin).Assembly.GetVersion());
                fileName = Path.Combine(Path.GetTempPath(), $"{pluginName}.zip");
                isTemp = true;

                Console.WriteLine($"Downloading from {address}");
                using (WebClient wc = new WebClient())
                {
                    wc.DownloadFile(address, fileName);
                }

                File.Copy(fileName, Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"update.zip"));
                if (!RSASign.GetAndVerifyZip(fileName)) return true;
            }
            else
            {
                fileName = pluginName;
                isTemp = false;
            }

            try
            {
                ZipFile.ExtractToDirectory(fileName, ".");
            }
            catch (IOException)
            {
                Console.WriteLine($"Plugin already exist.");
                return true;
            }
            finally
            {
                if (isTemp)
                {
                    File.Delete(fileName);
                }
            }

            Console.WriteLine($"Install successful, please restart bhp-cli.");
            return true;
        }
        */

        private bool OnInstallCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("error");
                return true;
            }

            bool isTemp;
            string fileName;
            string version = typeof(Plugin).Assembly.GetVersion();
            var pluginName = string.Concat(args[1], "-v", version, ".zip");

            if (!File.Exists(pluginName))
            {
                if (string.IsNullOrEmpty(Settings.Default.PluginURL))
                {
                    Console.WriteLine("You must define `PluginURL` in your `config.json`");
                    return true;
                }

                var address = string.Format(Settings.Default.PluginURL, version, pluginName);
                fileName = Path.Combine(Path.GetTempPath(), pluginName);
                isTemp = true;

                Console.WriteLine($"Downloading from {address}");
                using (WebClient wc = new WebClient())
                {
                    wc.DownloadFile(address, fileName);
                }
            }
            else
            {
                fileName = pluginName;
                isTemp = false;
            }

            try
            {
                ZipFile.ExtractToDirectory(fileName, "./Plugins");
            }
            catch (IOException)
            {
                Console.WriteLine($"Plugin already exist.");
                return true;
            }
            finally
            {
                if (isTemp)
                {
                    File.Delete(fileName);
                }
            }

            Console.WriteLine($"Install successful, please restart bhp-cli.");
            return true;
        }

        private bool OnUnInstallCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("error");
                return true;
            }
            var pluginName = args[1];

            if (!Plugin.Plugins.Any(u => u.Name == pluginName))
            {
                Console.WriteLine("Plugin not found");
                return true;
            }

            if (Directory.Exists(Path.Combine("Plugins", pluginName)))
            {
                Directory.Delete(Path.Combine("Plugins", pluginName), true);
            }

            File.Delete(Path.Combine("Plugins", $"{pluginName}.dll"));
            Console.WriteLine($"Uninstall successful, please restart bhp-cli.");
            return true;
        }

        private bool OnUpgradeWalletCommand(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("error");
                return true;
            }
            string path = args[2];
            if (Path.GetExtension(path) != ".db3")
            {
                Console.WriteLine("Can't upgrade the wallet file.");
                return true;
            }
            if (!File.Exists(path))
            {
                Console.WriteLine("File does not exist.");
                return true;
            }
            string password = ReadUserInput("password", true);
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            if (!RpcExtension.VerifyPW(password))
            {
                Console.WriteLine($"password max length {RpcExtension.MaxPWLength}");
                return true;
            }
            string path_new = Path.ChangeExtension(path, ".json");
            if (File.Exists(path_new))
            {
                Console.WriteLine($"File '{path_new}' already exists");
                return true;
            }
            BRC6Wallet.Migrate(GetIndexer(), path_new, path, password).Save();
            Console.WriteLine($"Wallet file upgrade complete. New wallet file has been auto-saved at: {path_new}");
            return true;
        }

        private static Wallet OpenWallet(WalletIndexer indexer, string path, string password)
        {
            if (Path.GetExtension(path) == ".db3")
            {
                return UserWallet.Open(indexer, path, password);
            }
            else
            {
                BRC6Wallet brc6wallet = new BRC6Wallet(indexer, path);
                brc6wallet.Unlock(password);
                return brc6wallet;
            }
        }
    }
}
