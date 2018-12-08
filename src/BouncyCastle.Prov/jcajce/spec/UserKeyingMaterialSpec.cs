namespace org.bouncycastle.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	public class UserKeyingMaterialSpec : AlgorithmParameterSpec
	{
		private readonly byte[] userKeyingMaterial;

		public UserKeyingMaterialSpec(byte[] userKeyingMaterial)
		{
			this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
		}

		public virtual byte[] getUserKeyingMaterial()
		{
			return Arrays.clone(userKeyingMaterial);
		}
	}

}