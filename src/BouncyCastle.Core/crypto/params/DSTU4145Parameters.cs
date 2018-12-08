namespace org.bouncycastle.crypto.@params
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class DSTU4145Parameters : ECDomainParameters
	{
		private readonly byte[] dke;

		public DSTU4145Parameters(ECDomainParameters ecParameters, byte[] dke) : base(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN(), ecParameters.getH(), ecParameters.getSeed())
		{

			this.dke = Arrays.clone(dke);
		}

		public virtual byte[] getDKE()
		{
			return Arrays.clone(dke);
		}
	}

}