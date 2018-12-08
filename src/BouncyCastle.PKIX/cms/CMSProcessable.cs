namespace org.bouncycastle.cms
{

	/// <summary>
	/// Use CMSTypedData instead of this. See CMSProcessableFile/ByteArray for defaults.
	/// </summary>
	public interface CMSProcessable
	{
		/// <summary>
		/// generic routine to copy out the data we want processed - the OutputStream
		/// passed in will do the handling on it's own.
		/// <para>
		/// Note: this routine may be called multiple times.
		/// </para>
		/// </summary>
		void write(OutputStream @out);

		object getContent();
	}

}