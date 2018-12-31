using org.bouncycastle.crypto.@params;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.newhope
{
		
	public class NHPrivateKeyParameters : AsymmetricKeyParameter
	{
		internal readonly short[] secData;

		public NHPrivateKeyParameters(short[] secData) : base(true)
		{

			this.secData = Arrays.clone(secData);
		}

		public virtual short[] getSecData()
		{
			return Arrays.clone(secData);
		}
	}

}