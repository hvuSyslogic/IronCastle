namespace org.bouncycastle.pqc.crypto.sphincs
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;

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