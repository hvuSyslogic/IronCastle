namespace org.bouncycastle.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Parameter spec for SM2 ID parameter
	/// </summary>
	public class SM2ParameterSpec : AlgorithmParameterSpec
	{
		private byte[] id;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="id"> the ID string associated with this usage of SM2. </param>
		public SM2ParameterSpec(byte[] id)
		{
			if (id == null)
			{
				throw new NullPointerException("id string cannot be null");
			}

			this.id = Arrays.clone(id);
		}

		/// <summary>
		/// Return the ID value.
		/// </summary>
		/// <returns> the ID string. </returns>
		public virtual byte[] getID()
		{
			return Arrays.clone(id);
		}
	}

}