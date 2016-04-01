using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptText3
{
    public interface IClipboardService
    {
        void CopyToClipboard(string text);
        bool IsImplemented { get; }
    }
}
