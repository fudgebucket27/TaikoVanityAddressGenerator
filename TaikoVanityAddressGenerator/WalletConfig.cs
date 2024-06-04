using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace TaikoVanityAddressGenerator
{
    public class WalletConfig
    {
        public string Owner { get; set; }
        public string[] Guardians { get; set; }
        public BigInteger Quota { get; set; }
        public string Inheritor { get; set; }
        public string FeeRecipient { get; set; }
        public string FeeToken { get; set; }
        public BigInteger MaxFeeAmount { get; set; }
        public BigInteger Salt { get; set; }
        public string Signature { get; set; }
    }
}
