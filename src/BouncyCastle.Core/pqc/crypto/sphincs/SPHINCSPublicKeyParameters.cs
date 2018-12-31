using org.bouncycastle.crypto.@params;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.sphincs
{
		
	public class SPHINCSPublicKeyParameters : AsymmetricKeyParameter
	{
		private readonly byte[] keyData;

		public SPHINCSPublicKeyParameters(byte[] keyData) : base(false)
		{
			this.keyData = Arrays.clone(keyData);
		}

		public virtual byte[] getKeyData()
		{
			return Arrays.clone(keyData);
		}
	}

}