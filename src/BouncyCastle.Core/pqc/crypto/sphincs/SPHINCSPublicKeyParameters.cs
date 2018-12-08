namespace org.bouncycastle.pqc.crypto.sphincs
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;

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