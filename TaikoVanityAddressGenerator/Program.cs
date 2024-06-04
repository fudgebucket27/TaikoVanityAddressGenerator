using System;
using System.Linq;
using System.Text;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Util;
using System.Security.Cryptography;
using Nethereum.ABI.FunctionEncoding;
using Nethereum.ABI;
using System.Numerics;

class Program
{
    static string WALLET_CREATION = "WALLET_CREATION";
  
    static void Main(string[] args)
    {
        string deployerAddress = "0xe7d8df8F6546965A59dab007e8709965Efe1255d"; //This is the deploy address of taiko l2 wallet on mainnet
        string ownerAddress = "0x36Cd6b3b9329c04df55d55D41C257a5fdD387ACd"; //Replace with your EOA owner address
        string desiredPattern = "0x69420"; //Your desired pattern at the start of the address.

        // Find the salt that generates the desired pattern
        string matchingSalt = FindVanityAddress(ownerAddress, deployerAddress, desiredPattern);
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
}
