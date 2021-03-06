﻿using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.pqc.crypto.ntru
{
	
	public class NTRUEncryptionKeyParameters : AsymmetricKeyParameter
	{
		protected internal readonly NTRUEncryptionParameters @params;

		public NTRUEncryptionKeyParameters(bool privateKey, NTRUEncryptionParameters @params) : base(privateKey)
		{
			this.@params = @params;
		}

		public virtual NTRUEncryptionParameters getParameters()
		{
			return @params;
		}
	}

}