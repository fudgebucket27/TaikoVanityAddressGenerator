using System;
using System.Linq;
using System.Text;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Util;
using System.Security.Cryptography;
using Nethereum.ABI.FunctionEncoding;
using Nethereum.ABI;
using System.Numerics;
using Nethereum.Signer;
using TaikoVanityAddressGenerator;
using Microsoft.Extensions.Configuration;

class Program
{
    static string WALLET_CREATION = "WALLET_CREATION";
  
    static void Main(string[] args)
    {
        IConfiguration configuration = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
        string deployerAddress = "0xe7d8df8F6546965A59dab007e8709965Efe1255d"; //This is the deploy address of taiko l2 wallet on mainnet
        string ownerAddress = "0xC14B11925dbfbb3Bfa174ABA8d5367766cC9C35E"; //Replace with your EOA owner address
        string desiredPattern = "0xfd6769"; //Your desired pattern at the start of the address.

        // Find the salt that generates the desired pattern
        //string matchingSalt = FindVanityAddress(ownerAddress, deployerAddress, desiredPattern);

        var config = new WalletConfig
        {
            Owner = ownerAddress,
            Guardians = new string[] {},
            Quota = 0,
            Inheritor = "0x0000000000000000000000000000000000000000",
            FeeRecipient = "0xDd2A08a1c1A28c1A571E098914cA10F2877D9c97",
            FeeToken = "0x0000000000000000000000000000000000000000",
            MaxFeeAmount = 0,
            Salt = 0
        };

        var domainSeparator = "0x1f1d6b4c09bd592e8dd1785e134cf53fa08bd604a010399ef9fc5c7766d4c87f "; 
        var signHash = WalletHelper.ComputeSignHash(config, domainSeparator);
        var privateKey =  configuration["PrivateKey"]; 
        var signature = WalletHelper.SignHash(signHash, privateKey);
        Console.WriteLine($"Signature: {signature}");
    }

    static string FindVanityAddress(string ownerAddress, string deployerAddress, string desiredPattern)
    {
        bool found = false;
        string saltHex = null;
        BigInteger saltUint256 = BigInteger.Zero;
        int count = 0;

        while (!found)
        {
            count++;
            // Generate a random salt
            saltHex = GenerateRandomSalt();

            // Compute the CREATE2 address
            string create2Address = ComputeCreate2Address(deployerAddress, saltHex, ownerAddress);

            // Check if the address matches the desired pattern
            if (create2Address.StartsWith(desiredPattern, StringComparison.OrdinalIgnoreCase))
            {
                saltUint256 = BigInteger.Parse(saltHex.Substring(2), System.Globalization.NumberStyles.HexNumber);
                Console.WriteLine($"Found matching address: {create2Address} with salt: {saltUint256}");
                Console.WriteLine($"Salt: {saltUint256}");
                found = true;
            }
        }
        return saltHex;
    }

    static string ComputeCreate2Address(string deployerAddress, string salt, string ownerAddress)
    {
        // Compute the wallet salt
        string walletSalt = ComputeWalletSalt(ownerAddress, salt);

        // Get the wallet code
        string walletCode = "0x608060405234801561001057600080fd5b506040516101a23803806101a28339818101604052602081101561003357600080fd5b50516001600160a01b03811661007a5760405162461bcd60e51b815260040180806020018281038252602481526020018061017e6024913960400191505060405180910390fd5b600080546001600160a01b039092166001600160a01b031990921691909117905560d5806100a96000396000f3fe608060405236603757604051339034907f8863e458255c600ae3e61be347822f3ee57088c8538b68b5dd2357e682e59e1990600090a3005b600073ffffffffffffffffffffffffffffffffffffffff8154167fa619486e0000000000000000000000000000000000000000000000000000000082351415608157808252602082f35b3682833781823684845af490503d82833e80609a573d82fd5b503d81f3fea2646970667358221220c8ef5c5147809cc480e3260788e027fa751bfcf051cf3d463bbaeeff798437f364736f6c63430007060033496e76616c6964206d617374657220636f707920616464726573732070726f766964656400000000000000000000000023a19a97a2da581e3d66ef5fd1eea15024f55611";

        // Compute the CREATE2 address
        string create2Address = ComputeCreate2AddressInternal(deployerAddress, walletSalt, walletCode);
        return create2Address;
    }

    static string ComputeWalletSalt(string ownerAddress, string salt)
    {
        byte[] ownerBytes = ownerAddress.HexToByteArray();
        byte[] saltBytes = salt.HexToByteArray();
        byte[] packedData = Encoding.UTF8.GetBytes(WALLET_CREATION).Concat(ownerBytes).Concat(saltBytes).ToArray();
        byte[] hashBytes = Sha3Keccack.Current.CalculateHash(packedData);
        return "0x" + BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }

    static string ComputeCreate2AddressInternal(string deployerAddress, string salt, string bytecode)
    {
        deployerAddress = deployerAddress.Substring(2);
        salt = salt.Substring(2);
        bytecode = bytecode.Substring(2);

        string dataToHash = "0xff" + deployerAddress + salt + Sha3Keccack.Current.CalculateHashFromHex(bytecode);
        byte[] hashBytes = Sha3Keccack.Current.CalculateHash(dataToHash.HexToByteArray());
        string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

        return "0x" + hash.Substring(24);
    }

    static string GenerateRandomSalt()
    {
        byte[] saltBytes = new byte[32];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }
        BigInteger salt = new BigInteger(saltBytes);
        salt = BigInteger.Abs(salt); // Ensure the salt is non-negative
        return "0x" + salt.ToString("x64");
    }

    public static class EIP712
    {
        public static string HashPacked(string domainSeparator, string dataHash)
        {
            var packedData = "0x1901" + domainSeparator.Substring(2) + dataHash.Substring(2);
            return Sha3Keccack.Current.CalculateHashFromHex(packedData);
        }
    }

    public static class WalletHelper
    {
        public static string ComputeSignHash(WalletConfig config, string domainSeparator)
        {
            var createWalletTypeHash = CreateWalletTypeHash();

            var guardiansHex = config.Guardians.Select(guardian => guardian.StartsWith("0x") ? guardian.Substring(2) : guardian).ToArray();
            var guardiansHash = Sha3Keccack.Current.CalculateHash(string.Join("", guardiansHex));

            var dataInput = string.Concat(
                createWalletTypeHash.Substring(2),
                config.Owner.StartsWith("0x") ? config.Owner.Substring(2) : config.Owner,
                guardiansHash,
                config.Quota.ToString("x"),
                config.Inheritor.StartsWith("0x") ? config.Inheritor.Substring(2) : config.Inheritor,
                config.FeeRecipient.StartsWith("0x") ? config.FeeRecipient.Substring(2) : config.FeeRecipient,
                config.FeeToken.StartsWith("0x") ? config.FeeToken.Substring(2) : config.FeeToken,
                config.MaxFeeAmount.ToString("x"),
                config.Salt.ToString("x")
            );

            var dataHash = Sha3Keccack.Current.CalculateHash(dataInput);

            var signHash = EIP712.HashPacked(domainSeparator, dataHash);
            return signHash;
        }

        public static string CreateWalletTypeHash()
        {
            string functionSignature = "createWallet(address owner,address[] guardians,uint256 quota,address inheritor,address feeRecipient,address feeToken,uint256 maxFeeAmount,uint256 salt)";
            string typeHash = Sha3Keccack.Current.CalculateHash(functionSignature);
            return typeHash;
        }


        public static string SignHash(string signHash, string privateKey)
        {
            var signer = new EthereumMessageSigner();
            var signature = signer.EncodeUTF8AndSign(signHash, new EthECKey(privateKey));
            return signature;
        }
    }
}
