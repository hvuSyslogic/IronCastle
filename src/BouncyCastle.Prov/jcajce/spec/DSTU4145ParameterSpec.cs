namespace org.bouncycastle.jcajce.spec
{

	using DSTU4145Params = org.bouncycastle.asn1.ua.DSTU4145Params;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ParameterSpec for a DSTU4145 key.
	/// </summary>
	public class DSTU4145ParameterSpec : ECParameterSpec
	{
		private readonly byte[] dke;
		private readonly ECDomainParameters parameters;

		public DSTU4145ParameterSpec(ECDomainParameters parameters) : this(parameters, EC5Util.convertToSpec(parameters), DSTU4145Params.getDefaultDKE())
		{
		}

		private DSTU4145ParameterSpec(ECDomainParameters parameters, ECParameterSpec ecParameterSpec, byte[] dke) : base(ecParameterSpec.getCurve(), ecParameterSpec.getGenerator(), ecParameterSpec.getOrder(), ecParameterSpec.getCofactor())
		{

			this.parameters = parameters;
			this.dke = Arrays.clone(dke);
		}

		public virtual byte[] getDKE()
		{
			return Arrays.clone(dke);
		}

		public override bool Equals(object o)
		{
			if (o is DSTU4145ParameterSpec)
			{
				DSTU4145ParameterSpec other = (DSTU4145ParameterSpec)o;

				return this.parameters.Equals(other.parameters);
			}

			return false;
		}

		public override int GetHashCode()
		{
			return this.parameters.GetHashCode();
		}
	}

}