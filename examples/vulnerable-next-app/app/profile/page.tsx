export default function ProfilePage() {
  const profileHtml = "<h1>Demo profile</h1>";
  return <main dangerouslySetInnerHTML={{ __html: profileHtml }} />;
}
