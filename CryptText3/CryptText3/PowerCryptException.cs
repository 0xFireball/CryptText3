using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptText3
{
    public class PowerCryptException : Exception
    {
        public PowerCryptException(string message) : base(message) { }
    }
}
