<template>
    <div>
        <div class="form-inline d-flex align-items-center mb-2">
            <b-button class="mr-1" @click="gotoFirstPage" title="go to first page">
                <font-awesome-icon icon="home" />
            </b-button>
            <b-button id="create-new-lib" v-b-toggle.collapse-2 v-if="isAdmin" title="Create new folder" class="mr-1">
                <font-awesome-icon icon="plus" />
                Library
            </b-button>
            <SearchField :typingDelay="0" @updateSearch="searchValue($event)" />
            <b-form-checkbox class="mr-1" @input="toggle_include_deleted($event)">
                include deleted
            </b-form-checkbox>
            <b-form-checkbox class="mr-1" @input="toggle_exclude_restricted($event)">
                exclude restricted
            </b-form-checkbox>
        </div>
        <b-collapse v-model="isNewLibFormVisible" id="collapse-2">
            <b-card>
                <b-form @submit.prevent="newLibrary">
                    <b-input-group class="mb-2 new-row">
                        <b-form-input v-model="newLibraryForm.name" required placeholder="Name" />
                        <b-form-input v-model="newLibraryForm.description" required placeholder="Description" />
                        <b-form-input v-model="newLibraryForm.synopsis" placeholder="Synopsis" />
                        <template v-slot:append>
                            <b-button id="save_new_library" type="submit" title="save">
                                <font-awesome-icon :icon="['far', 'save']" />
                                Save
                            </b-button>
                        </template>
                    </b-input-group>
                </b-form>
            </b-card>
        </b-collapse>
        <b-table
            id="libraries_list"
            striped
            hover
            :fields="fields"
            :items="librariesList"
            :per-page="perPage"
            :current-page="currentPage"
            show-empty
            ref="libraries_list"
            @filtered="onFiltered"
            :filter="filter"
            :filterIncludedFields="filterOn"
        >
            <template v-slot:cell(name)="row">
                <textarea
                    v-if="row.item.editMode"
                    class="form-control input_library_name"
                    :ref="`name-${row.item.id}`"
                    :value="row.item.name"
                    rows="3"
                />

                <div class="deleted-item" v-else-if="row.item.deleted && include_deleted">{{ row.item.name }}</div>
                <b-link v-else :to="{ path: `folders/${row.item.root_folder_id}` }">{{ row.item.name }}</b-link>
            </template>
            <template v-slot:cell(description)="row">
                <LibraryEditField
                    @toggleDescriptionExpand="toggleDescriptionExpand(row.item)"
                    :ref="`description-${row.item.id}`"
                    :isExpanded="row.item.isExpanded"
                    :isEditMode="row.item.editMode"
                    :text="row.item.description"
                />
            </template>
            <template v-slot:cell(synopsis)="row">
                <LibraryEditField
                    @toggleDescriptionExpand="toggleDescriptionExpand(row.item)"
                    :ref="`synopsis-${row.item.id}`"
                    :isExpanded="row.item.isExpanded"
                    :isEditMode="row.item.editMode"
                    :text="row.item.synopsis"
                />
            </template>
            <template v-slot:cell(is_unrestricted)="row">
                <font-awesome-icon
                    v-if="row.item.public && !row.item.deleted"
                    title="Unrestricted dataset"
                    icon="globe"
                />
            </template>
            <template v-slot:cell(buttons)="row">
                <b-button @click="undelete(row.item)" v-if="row.item.deleted" :title="'Undelete ' + row.item.name">
                    <font-awesome-icon icon="unlock" />
                    Undelete
                </b-button>
                <div v-else>
                    <b-button
                        v-if="row.item.can_user_modify && row.item.editMode"
                        size="sm"
                        class="lib-btn permission_folder_btn"
                        :title="'Permissions of ' + row.item.name"
                        @click="saveChanges(row.item)"
                    >
                        <font-awesome-icon :icon="['far', 'save']" />
                        Save
                    </b-button>
                    <b-button
                        v-if="row.item.can_user_modify"
                        size="sm"
                        class="lib-btn edit_library_btn save_library_btn"
                        :title="`Edit ${row.item.name}`"
                        @click="toggleEditMode(row.item)"
                    >
                        <div v-if="!row.item.editMode">
                            <font-awesome-icon icon="pencil-alt" />
                            Edit
                        </div>
                        <div v-else>
                            <font-awesome-icon :icon="['fas', 'times']" />
                            Cancel
                        </div>
                    </b-button>
                    <b-button
                        v-if="row.item.can_user_manage && !row.item.editMode"
                        size="sm"
                        class="lib-btn permission_library_btn"
                        :title="'Permissions of ' + row.item.name"
                        :href="`${root}library/list#library/${row.item.id}/permissions`"
                    >
                        <font-awesome-icon icon="users" />
                        Manage
                    </b-button>
                    <b-button
                        v-if="row.item.editMode"
                        size="sm"
                        class="lib-btn delete-lib-btn"
                        :title="`Delete ${row.item.name}`"
                        @click="deleteLibrary(row.item)"
                    >
                        <font-awesome-icon icon="trash" />
                        Delete
                    </b-button>
                </div>
            </template>
        </b-table>

        <b-container>
            <b-row class="justify-content-md-center">
                <b-col md="auto">
                    <b-pagination
                        v-model="currentPage"
                        :total-rows="rows"
                        :per-page="perPage"
                        aria-controls="libraries_list"
                    >
                    </b-pagination>
                </b-col>
                <b-col cols="1.5">
                    <table>
                        <tr>
                            <td class="m-0 p-0">
                                <b-form-input
                                    class="pagination-input-field"
                                    id="paginationPerPage"
                                    autocomplete="off"
                                    type="number"
                                    v-model="perPage"
                                />
                            </td>
                            <td class="text-muted ml-1 paginator-text">
                                <span class="pagination-total-pages-text">per page, {{ rows }} total</span>
                            </td>
                        </tr>
                    </table>
                </b-col>
            </b-row>
        </b-container>
    </div>
</template>

<script>
import Vue from "vue";
import { getGalaxyInstance } from "app";
import { getAppRoot } from "onload/loadConfig";
import BootstrapVue from "bootstrap-vue";
import { Services } from "./services";
import { fields } from "./table-fields";
import { Toast } from "ui/toast";
import { initLibariesIcons } from "components/Libraries/icons";
import { MAX_DESCRIPTION_LENGTH, DEFAULT_PER_PAGE, onError } from "components/Libraries/library-utils";
import LibraryEditField from "components/Libraries/LibraryEditField";
import SearchField from "components/Libraries/LibraryFolder/SearchField";

import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";

initLibariesIcons();

Vue.use(BootstrapVue);

export default {
    components: {
        FontAwesomeIcon,
        LibraryEditField,
        SearchField,
    },
    computed: {
        rows() {
            return this.librariesList.length;
        },
    },
    data() {
        const galaxy = getGalaxyInstance();
        return {
            isNewLibFormVisible: false,
            currentPage: 1,
            fields: fields,
            perPage: DEFAULT_PER_PAGE,
            librariesList: [],
            maxDescriptionLength: MAX_DESCRIPTION_LENGTH,
            include_deleted: false,
            exclude_restricted: false,
            filterOn: [],
            excluded: [],
            filter: null,
            isAdmin: galaxy.user.isAdmin(),
            newLibraryForm: {
                name: "",
                description: "",
                synopsis: "",
            },
        };
    },
    created() {
        this.root = getAppRoot();
        this.services = new Services({ root: this.root });
        this.loadLibraries(this.include_deleted);
    },
    methods: {
        loadLibraries(include_deleted = false) {
            this.services.getLibraries(include_deleted).then((result) => (this.librariesList = result));
        },
        toggleEditMode(item) {
            item.editMode = !item.editMode;
            this.$refs.libraries_list.refresh();
        },
        toggleDescriptionExpand(item) {
            item.isExpanded = !item.isExpanded;
            this.$refs.libraries_list.refresh();
        },
        saveChanges(item) {
            item.description = this.$refs[`description-${item.id}`].textField;
            item.synopsis = this.$refs[`synopsis-${item.id}`].textField;
            this.services.saveChanges(
                item,
                () => {
                    Toast.success("Changes to library saved");
                },
                (error) => onError(error)
            );
            this.toggleEditMode(item);
        },
        deleteLibrary(deletedLib) {
            this.services.deleteLibrary(
                deletedLib,
                () => {
                    Toast.success("Library has been marked deleted.");
                    deletedLib.deleted = true;
                    this.toggleEditMode(deletedLib);
                    if (!this.include_deleted) this.hideOn("deleted", false);
                },
                (error) => onError(error)
            );
        },
        gotoFirstPage() {
            this.currentPage = 1;
        },
        onFiltered(filteredItems) {
            // Trigger pagination to update the number of buttons/pages due to filtering
            this.totalRows = filteredItems.length;
            this.currentPage = 1;
        },
        searchValue(value) {
            this.filter = value;
        },
        toggle_include_deleted(isDeletedIncluded) {
            this.include_deleted = isDeletedIncluded;
            if (this.include_deleted) {
                this.services.getLibraries(this.include_deleted).then((result) => {
                    this.librariesList = this.librariesList.concat(result);
                    this.$refs.libraries_list.refresh();
                });
            } else {
                this.hideOn("deleted", false);
            }
        },
        toggle_exclude_restricted(isRestrictedIncluded) {
            this.exclude_restricted = isRestrictedIncluded;
            if (this.exclude_restricted) {
                this.excluded = this.hideOn("public", true);
            } else {
                this.librariesList = this.librariesList.concat(this.excluded);
            }
        },
        hideOn(property, value) {
            const filtered = [];
            this.librariesList = this.librariesList.filter((lib) => {
                if (lib[property] === value) return lib;
                else filtered.push(lib);
            });
            return filtered;
        },
        undelete(item) {
            this.services.deleteLibrary(
                item,
                () => {
                    item.deleted = false;
                    Toast.success("Library has been undeleted.");
                    this.$refs.libraries_list.refresh();
                },
                (error) => onError(error),
                true
            );
        },
        newLibrary() {
            this.services.createNewLibrary(
                this.newLibraryForm.name,
                this.newLibraryForm.description,
                this.newLibraryForm.synopsis,
                (newLib) => {
                    this.librariesList.push(newLib);
                    this.newLibraryForm.name = "";
                    this.newLibraryForm.description = "";
                    this.newLibraryForm.synopsis = "";
                    this.isNewLibFormVisible = false;
                    Toast.success("Library created.");
                },
                (error) => onError(error)
            );
        },
    },
};
</script>
<style scoped>
.deleted-item {
    cursor: not-allowed;
    color: gray;
}
</style>
