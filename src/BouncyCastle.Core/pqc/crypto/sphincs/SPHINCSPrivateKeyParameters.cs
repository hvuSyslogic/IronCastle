using org.bouncycastle.crypto.@params;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.sphincs
{
		
	public class SPHINCSPrivateKeyParameters : AsymmetricKeyParameter
	{
		private readonly byte[] keyData;

		public SPHINCSPrivateKeyParameters(byte[] keyData) : base(true)
		{
			this.keyData = Arrays.clone(keyData);
		}

		public virtual byte[] getKeyData()
		{
			return Arrays.clone(keyData);
		}
	}

}