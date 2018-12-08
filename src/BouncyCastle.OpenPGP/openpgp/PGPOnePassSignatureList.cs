namespace org.bouncycastle.openpgp
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Iterable = org.bouncycastle.util.Iterable;

	/// <summary>
	/// Holder for a list of PGPOnePassSignatures
	/// </summary>
	public class PGPOnePassSignatureList : Iterable<PGPOnePassSignature>
	{
		internal PGPOnePassSignature[] sigs;

		public PGPOnePassSignatureList(PGPOnePassSignature[] sigs)
		{
			this.sigs = new PGPOnePassSignature[sigs.Length];

			JavaSystem.arraycopy(sigs, 0, this.sigs, 0, sigs.Length);
		}

		public PGPOnePassSignatureList(PGPOnePassSignature sig)
		{
			this.sigs = new PGPOnePassSignature[1];
			this.sigs[0] = sig;
		}

		public virtual PGPOnePassSignature get(int index)
		{
			return sigs[index];
		}

		public virtual int size()
		{
			return sigs.Length;
		}

		public virtual bool isEmpty()
		{
			return (sigs.Length == 0);
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator<PGPOnePassSignature> iterator()
		{
			return new Arrays.Iterator(sigs);
		}
	}

}