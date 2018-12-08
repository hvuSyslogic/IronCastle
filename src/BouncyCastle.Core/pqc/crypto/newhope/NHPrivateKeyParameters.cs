namespace org.bouncycastle.pqc.crypto.newhope
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;

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