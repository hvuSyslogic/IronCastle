namespace org.bouncycastle.pqc.crypto.newhope
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;

	public class NHPublicKeyParameters : AsymmetricKeyParameter
	{
		internal readonly byte[] pubData;

		public NHPublicKeyParameters(byte[] pubData) : base(false)
		{
			this.pubData = Arrays.clone(pubData);
		}

		/// <summary>
		/// Return the public key data.
		/// </summary>
		/// <returns> the public key values. </returns>
		public virtual byte[] getPubData()
		{
			return Arrays.clone(pubData);
		}
	}

}