# Copyright 2016 ATT Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging

from six import moves

from role_out.tests.api import rbac_base
from role_out.rbac_mixin import BaseRbacTest as mixin
from tempest.lib.common.utils import data_utils
from tempest import test

from role_out import rbac_exceptions
from role_out import rbac_rule_validation
from role_out.rbac_utils import rbac_utils
from tempest import config

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BasicOperationsImagesRbacTest(rbac_base.BaseV2ImageRbacTest):

    mixin.credentials

    @classmethod
    def skip_checks(cls):
        super(BasicOperationsImagesRbacTest, cls).skip_checks()
        mixin.skip_checks()

    @classmethod
    def setup_credentials(cls):
        super(BasicOperationsImagesRbacTest, cls).setup_credentials()
        cls.auth_provider = cls.os.auth_provider

    @classmethod
    def setup_clients(cls):
        super(BasicOperationsImagesRbacTest, cls).setup_clients()
        cls.client = cls.os.image_client_v2
        cls.admin_client = cls.adm_client = cls.os_adm.image_client_v2

    @rbac_rule_validation.action(component="Image", rule="add_image")
    @test.idempotent_id('0f148510-63bf-11e6-b348-080027d0d606')
    def test_create_image(self):

        """
            Create Image Test
        """
        try:
            uuid = '00000000-1111-2222-3333-444455556666'
            image_name = data_utils.rand_name('image')
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.create_image(name=image_name,
                              container_format='bare',
                              disk_format='raw',
                              visibility='private',
                              ramdisk_id=uuid)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Image", rule="upload_image")
    @test.idempotent_id('fdc0c7e2-ad58-4c5a-ba9d-1f6046a5b656')
    def test_upload_image(self):

        """
            Upload Image Test
        """
        uuid = '00000000-1111-2222-3333-444455556666'
        image_name = data_utils.rand_name('image')
        body = self.create_image(name=image_name,
                                 container_format='bare',
                                 disk_format='raw',
                                 visibility='private',
                                 ramdisk_id=uuid)

        try:
            rbac_utils.switch_role(self, switchToRbacRole=True)
            # Try uploading an image file
            image_file = moves.cStringIO(data_utils.random_bytes())
            self.client.store_image_file(body['id'], image_file)
        except ValueError as e:
            '''ValueError is being thrown when role doesn't have permission to
            upload file when creating an image'''
            LOG.info("ValueError is being thrown when role doesn't have "
                     "permission to upload file when creating an image")
            raise rbac_exceptions.RbacActionFailed(e)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Image", rule="delete_image")
    @test.idempotent_id('3b5c341e-645b-11e6-ac4f-080027d0d606')
    def test_delete_image(self):

        """
            Delete created image
        """
        try:
            image_name = data_utils.rand_name('image')
            body = self.client.create_image(name=image_name,
                                            container_format='bare',
                                            disk_format='raw',
                                            visibility='public')
            image_id = body.get('id')
            # Toggle role and delete created image
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.client.delete_image(image_id)
            self.client.wait_for_resource_deletion(image_id)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)
            images = self.client.list_images()['images']
            images = [image['id'] for image in images]
            if image_id in images:
                self.client.delete_image(image_id)
                self.client.wait_for_resource_deletion(image_id)

    @rbac_rule_validation.action(component="Image", rule="get_image")
    @test.idempotent_id('3085c7c6-645b-11e6-ac4f-080027d0d606')
    def test_show_image(self):

        """
            Get created image
        """
        try:
            image_name = data_utils.rand_name('image')
            body = self.client.create_image(name=image_name,
                                            container_format='bare',
                                            disk_format='raw',
                                            visibility='private')
            image_id = body.get('id')
            self.addCleanup(self.client.delete_image, image_id)
            # Toggle role and get created image
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.client.show_image(image_id)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Image", rule="get_images")
    @test.idempotent_id('bf1a4e94-645b-11e6-ac4f-080027d0d606')
    def test_list_images(self):

        """
            List all the images
        """
        try:
            # Toggle role and get created image
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.client.list_images()
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Image", rule="modify_image")
    @test.idempotent_id('32ecf48c-645e-11e6-ac4f-080027d0d606')
    def test_update_image(self):

        """
            Update given images
        """
        try:
            image_name = data_utils.rand_name('image')
            body = self.client.create_image(name=image_name,
                                            container_format='bare',
                                            disk_format='raw',
                                            visibility='private')
            image_id = body.get('id')
            self.addCleanup(self.client.delete_image, image_id)

            # Now try uploading an image file
            image_file = moves.cStringIO(data_utils.random_bytes())
            self.client.store_image_file(image_id, image_file)

            # Toggle role and update created image
            rbac_utils.switch_role(self, switchToRbacRole=True)
            new_image_name = data_utils.rand_name('new-image')
            body = self.client.update_image(image_id, [
                dict(replace='/name', value=new_image_name)])
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Image", rule="publicize_image")
    @test.idempotent_id('0ea4809c-6461-11e6-ac4f-080027d0d606')
    def test_publicize_image(self):

        """
            Publicize Image
        """
        try:
            image_name = data_utils.rand_name('image')
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.create_image(name=image_name,
                              container_format='bare',
                              disk_format='raw',
                              visibility='public')
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Image",
                                 rule="download_image")
    @test.idempotent_id('80d636e2-652e-11e6-90b6-080027824017')
    def test_download_image(self):

        """
            Download Image Test
        """
        try:
            uuid = '00000000-1111-2222-3333-444455556666'
            image_name = data_utils.rand_name('image')
            body = self.create_image(name=image_name,
                                     container_format='bare',
                                     disk_format='raw',
                                     visibility='private',
                                     ramdisk_id=uuid)
            image_id = body.get('id')
            # Now try uploading an image file
            image_file = moves.cStringIO(data_utils.random_bytes())
            self.client.store_image_file(image_id=image_id, data=image_file)
            # Toggling role and download image
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.client.download_image(image_id)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Image",
                                 rule="deactivate")
    @test.idempotent_id('b488458c-65df-11e6-9947-080027824017')
    def test_deactivate_image(self):

        """
            Deactivate Image Test
        """
        try:
            uuid = '00000000-1111-2222-3333-444455556666'
            image_name = data_utils.rand_name('image')
            body = self.create_image(name=image_name,
                                     container_format='bare',
                                     disk_format='raw',
                                     visibility='private',
                                     ramdisk_id=uuid)
            image_id = body.get('id')
            # Now try uploading an image file
            image_file = moves.cStringIO(data_utils.random_bytes())
            self.client.store_image_file(image_id=image_id, data=image_file)
            # Toggling role and deacivate image
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.client.deactivate_image(image_id)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

    @rbac_rule_validation.action(component="Image",
                                 rule="reactivate")
    @test.idempotent_id('d3fa28b8-65df-11e6-9947-080027824017')
    def test_reactivate_image(self):

        """
            Reactivate Image Test
        """
        try:
            uuid = '00000000-1111-2222-3333-444455556666'
            image_name = data_utils.rand_name('image')
            body = self.create_image(name=image_name,
                                     container_format='bare',
                                     disk_format='raw',
                                     visibility='private',
                                     ramdisk_id=uuid)

            # Now try uploading an image file
            image_id = body.get('id')
            image_file = moves.cStringIO(data_utils.random_bytes())
            self.client.store_image_file(image_id=image_id, data=image_file)
            # Toggling role and reactivate image
            rbac_utils.switch_role(self, switchToRbacRole=True)
            self.client.reactivate_image(image_id)
        finally:
            rbac_utils.switch_role(self, switchToRbacRole=False)

