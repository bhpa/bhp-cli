using Microsoft.Extensions.Configuration;
using Bhp.Network.P2P;
using System.Net;
using Bhp.SmartContract.Native;
using System.Threading;

namespace Bhp
{
    internal class Settings
    {
        public PathsSettings Paths { get; }
        public P2PSettings P2P { get; }
        public RPCSettings RPC { get; }
        public UnlockWalletSettings UnlockWallet { get; }
        public string PluginURL { get; }
        public DataRPCSettings DataRPC { get; set; }
        public ExportWalletSettings ExportWallet { get; set; }

        static Settings _default;

        static bool UpdateDefault(IConfiguration configuration)
        {
            var settings = new Settings(configuration.GetSection("ApplicationConfiguration"));
            return null == Interlocked.CompareExchange(ref _default, settings, null);
        }

        public static bool Initialize(IConfiguration configuration)
        {
            return UpdateDefault(configuration);
        }

        public static Settings Default
        {
            get
            {
                if (_default == null)
                {
                    UpdateDefault(Helper.LoadConfig("config"));
                }

                return _default;
            }
        }

        public Settings(IConfigurationSection section)
        {
            this.Paths = new PathsSettings(section.GetSection("Paths"));
            this.P2P = new P2PSettings(section.GetSection("P2P"));
            this.RPC = new RPCSettings(section.GetSection("RPC"));
            this.UnlockWallet = new UnlockWalletSettings(section.GetSection("UnlockWallet"));
            this.PluginURL = section.GetSection("PluginURL").Value;
            DataRPC = new DataRPCSettings(section.GetSection("DataRPC"));
            this.ExportWallet = new ExportWalletSettings(section.GetSection("ExportWallet"));
        }
    }

    internal class PathsSettings
    {
        public string Chain { get; }
        public string Index { get; }

        public PathsSettings(IConfigurationSection section)
        {
            this.Chain = string.Format(section.GetSection("Chain").Value, ProtocolSettings.Default.Magic.ToString("X8"));
            this.Index = string.Format(section.GetSection("Index").Value, ProtocolSettings.Default.Magic.ToString("X8"));
        }
    }

    internal class P2PSettings
    {
        public ushort Port { get; }
        public ushort WsPort { get; }
        public int MinDesiredConnections { get; }
        public int MaxConnections { get; }
        public int MaxConnectionsPerAddress { get; }

        public P2PSettings(IConfigurationSection section)
        {
            this.Port = ushort.Parse(section.GetSection("Port").Value);
            this.WsPort = ushort.Parse(section.GetSection("WsPort").Value);
            this.MinDesiredConnections = section.GetValue("MinDesiredConnections", Peer.DefaultMinDesiredConnections);
            this.MaxConnections = section.GetValue("MaxConnections", Peer.DefaultMaxConnections);
            this.MaxConnectionsPerAddress = section.GetValue("MaxConnectionsPerAddress", 3);
        }
    }

    internal class RPCSettings
    {
        public IPAddress BindAddress { get; }
        public ushort Port { get; }
        public string SslCert { get; }
        public string SslCertPassword { get; }
        public long MaxGasInvoke { get; }

        public RPCSettings(IConfigurationSection section)
        {
            this.BindAddress = IPAddress.Parse(section.GetSection("BindAddress").Value);
            this.Port = ushort.Parse(section.GetSection("Port").Value);
            this.SslCert = section.GetSection("SslCert").Value;
            this.SslCertPassword = section.GetSection("SslCertPassword").Value;
            this.MaxGasInvoke = (long)BigDecimal.Parse(section.GetValue("MaxGasInvoke", "10"), NativeContract.GAS.Decimals).Value;
        }
    }

    public class UnlockWalletSettings
    {
        public string Path { get; }
        public string Password { get; }
        public bool StartConsensus { get; }
        public bool IsActive { get; }
        public bool AutoLock { get; }
        public bool IsBhpFee { get; }

        public UnlockWalletSettings(IConfigurationSection section)
        {
            if (section.Exists())
            {
                this.Path = section.GetSection("Path").Value;
                this.Password = section.GetSection("Password").Value;
                this.StartConsensus = bool.Parse(section.GetSection("StartConsensus").Value);
                this.IsActive = bool.Parse(section.GetSection("IsActive").Value);
                this.AutoLock = bool.Parse(section.GetSection("AutoLock").Value);
                this.IsBhpFee = bool.Parse(section.GetSection("IsBhpFee").Value);
            }
        }
    }

    internal class DataRPCSettings
    {
        public string Host { get; }

        public DataRPCSettings(IConfigurationSection section)
        {
            if (section != null)
            {
                Host = section.GetSection("Host").Value;
            }
        }
    }

    internal class ExportWalletSettings
    {
        public string Path { get; }
        public int Interval { get; }
        public bool IsActive { get; }

        public ExportWalletSettings(IConfigurationSection section)
        {
            if (section.Exists())
            {
                this.Path = section.GetSection("Path").Value;
                this.Interval = int.Parse(section.GetSection("Interval").Value);
                if (this.Interval <= 0)
                {
                    this.Interval = 8;
                }
                this.IsActive = bool.Parse(section.GetSection("IsActive").Value);
            }
        }
    }
}
