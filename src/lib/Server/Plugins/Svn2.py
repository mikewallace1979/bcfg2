import os
try:
    import pysvn
    missing = False
except:
    missing = True
import Bcfg2.Server.Plugin

# FIXME
REPOS_URL = 'file:///space/svn/admin'

class Svn2(Bcfg2.Server.Plugin.Plugin,
          Bcfg2.Server.Plugin.Version):
    """Svn is a version plugin for dealing with Bcfg2 repos."""
    name = 'Svn2'
    __version__ = '$Id$'
    __author__ = 'bcfg-dev@mcs.anl.gov'

    conflicts = ['Svn']
    experimental = True
    __rmi__ = Bcfg2.Server.Plugin.Plugin.__rmi__ + ['Update']

    def __init__(self, core, datastore):
        Bcfg2.Server.Plugin.Plugin.__init__(self, core, datastore)

        if missing:
            self.logger.error("Svn2: Missing PySvn")
            raise Bcfg2.Server.Plugin.PluginInitError

        self.client = pysvn.Client()

        self.core = core
        self.datastore = datastore
        self.svn_root = REPOS_URL
        self.revision = None

        # Read revision from bcfg2 repo
        revision = self.get_revision()
        if not self.revision:
            raise Bcfg2.Server.Plugin.PluginInitError

        self.logger.debug("Initialized svn plugin with svn root %s at revision %s" \
            % (self.svn_root, revision))

    def get_revision(self):
        """Read svn revision information for the Bcfg2 repository."""
        try:
            info = self.client.info(self.datastore)
            self.revision = info.revision
            return str(self.revision.number)
        except:
            self.logger.error("Svn2: Failed to get revision", exc_info=1)
            self.revision = None
        return str(-1)

    def Update(self):
        '''NatvieSvn.Update() => True|False\nUpdate svn working copy\n'''
        try:
            old_revision = self.revision.number
            self.revision = self.client.update(self.datastore, recurse=True)[0]
        except:
            self.logger.error("Svn2: Failed to update server repository", exc_info=1)
            return False

        if old_revision == self.revision.number:
            self.logger.debug("repository is current")
        else:
            self.logger.info("Updated %s from revision %s to %s" % \
                (self.datastore, old_revision, self.revision.number))
        return True

